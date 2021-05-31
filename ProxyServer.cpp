#include <regex>
#include <thread>
#include <mutex>
#include <tuple>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <netdb.h>
#include <string>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libconfig.h++>
#include "sqlite3.h"
#define DEFAULT_HTTP_PORT 80
#define TCPBUFFER_SIZE 0xFFFF
#define RCV_TIMEOUT_SEC 5
using namespace libconfig;

sqlite3* ConnDB;
std::mutex PrintMtx;
bool WhiteBlackListMode; //true - white, false - black
void MsgPrint(std::string msg);
void Rerouting(int Host_Proxy);
void Redirect(int Socket);
void ResponseOnGET(int Socket);
void Response403(int _Host_Proxy);
void Conrtoller(int Host_AdmPnl);
void AdminPanelHandler(std::string ip, int port);
void AddingRecord(int Socket, std::string httpRequest);
void DeletingRecord(int Socket, std::string httpRequest);
bool BlackRules(std::string _Host, std::string _IP);
bool WhiteRules(std::string _Host, std::string _IP);
std::tuple<std::string, unsigned short> ParsingTCP(std::string httpRequest);

int main()
{
    Config cfg;
    try{
        cfg.readFile("Boot.cfg");
    }
    catch(...){
        printf("ERROR. Config file not found\n");
        exit(1);
    }
    WhiteBlackListMode = cfg.lookup("WhiteMode");
    std::string DBname = cfg.lookup("DBname");
    std::string IP = cfg.lookup("IP");
    int PORT = cfg.lookup("Port");
    int PORT_ADMIN_PANEL = cfg.lookup("PortAdmin");
    sqlite3_open(("./Resources/"+DBname).c_str(), &ConnDB);
    std::thread AdminPanel(AdminPanelHandler, IP, PORT_ADMIN_PANEL);
    AdminPanel.detach();
    MsgPrint(WhiteBlackListMode ? "WhiteList mode activated": "BlackList mode activated");

    int New_connection;
    int PROXY_SERVER = socket(AF_INET, SOCK_STREAM, NULL);
    sockaddr_in PROXY_SOCKADDR;
    PROXY_SOCKADDR.sin_addr.s_addr = inet_addr(IP.c_str());
    PROXY_SOCKADDR.sin_port = htons(PORT);
    PROXY_SOCKADDR.sin_family = AF_INET;
    unsigned int SIZE_OF_ADDR_PROXY = sizeof(PROXY_SOCKADDR);

    bind(PROXY_SERVER, (sockaddr*)&PROXY_SOCKADDR, sizeof(PROXY_SOCKADDR));
    listen(PROXY_SERVER, SOMAXCONN);
    MsgPrint("Proxy is listening on " + IP + ":" + std::to_string(PORT));
    MsgPrint("Server started...");

    while (1) {
        New_connection = accept(PROXY_SERVER, (sockaddr*)&PROXY_SOCKADDR, &SIZE_OF_ADDR_PROXY);
        if (New_connection != 0) {
            std::thread th(Rerouting, New_connection);
            th.detach();
        }
    }

    close(New_connection);
    close(PROXY_SERVER);
    sqlite3_close(ConnDB);
    exit(0);
}

void Rerouting(int Host_Proxy)
{
    char* TCPBuffer = new char[TCPBUFFER_SIZE]{};
    int ParcelTCP_Size = recv(Host_Proxy, TCPBuffer, TCPBUFFER_SIZE, NULL);

    auto HostPort = ParsingTCP((std::string)TCPBuffer);
    if (std::get<1>(HostPort) == 0) {
        close(Host_Proxy);
        delete[] TCPBuffer;
        MsgPrint("Something went wrong during parsing a TCP request");
        return;
    }
    auto ip = gethostbyname(std::get<0>(HostPort).c_str());
    if (ip == NULL) {
        close(Host_Proxy);
        delete[] TCPBuffer;
        return;
    }
    std::string IPHost = inet_ntoa(*(in_addr*)ip->h_addr_list[0]);

    bool AllowConnection = WhiteBlackListMode ? WhiteRules(std::get<0>(HostPort), IPHost) : BlackRules(std::get<0>(HostPort), IPHost);

    if (!AllowConnection) {
        Response403(Host_Proxy);
        shutdown(Host_Proxy, SHUT_WR);  // отключаем соединение на обратный посыл
        close(Host_Proxy);              // уничтожаем сокет
        delete[] TCPBuffer;
        MsgPrint("Access to " + std::get<0>(HostPort) + "(" + IPHost + ") is denied!");
        return;
    }

    if (((std::string)TCPBuffer).find("GET ") == -1 && ((std::string)TCPBuffer).find("POST ") == -1) {//if no GET or POST request
        close(Host_Proxy);
        delete[] TCPBuffer;
        return;
    }
    MsgPrint("Request for " + std::get<0>(HostPort) + "(" + IPHost + ") received");

    int Proxy_Web = socket(AF_INET, SOCK_STREAM, NULL);
    sockaddr_in Proxy_Web_sockaddr;
    Proxy_Web_sockaddr.sin_addr.s_addr = inet_addr(IPHost.c_str());
    Proxy_Web_sockaddr.sin_port = htons(std::get<1>(HostPort));
    Proxy_Web_sockaddr.sin_family = AF_INET;
    struct timeval Timeout;
    Timeout.tv_sec = RCV_TIMEOUT_SEC;
    setsockopt(Proxy_Web, SOL_SOCKET, SO_RCVTIMEO, &Timeout, sizeof(Timeout));

    if (connect(Proxy_Web, (sockaddr*)&Proxy_Web_sockaddr, sizeof(Proxy_Web_sockaddr)) != 0) {
        close(Proxy_Web);
        close(Host_Proxy);
        delete[] TCPBuffer;
        MsgPrint("Can't connect to " + std::get<0>(HostPort) + "(" + IPHost + ")");
        return;
    }

    if (send(Proxy_Web, ((std::string)TCPBuffer).c_str(), ParcelTCP_Size, NULL) != ParcelTCP_Size) {
        close(Proxy_Web);
        close(Host_Proxy);
        delete[] TCPBuffer;
        MsgPrint("Error sending request to " + std::get<0>(HostPort) + "(" + IPHost + ")");
        return;
    }

    do {
        memset(TCPBuffer, 0, TCPBUFFER_SIZE);
        ParcelTCP_Size = recv(Proxy_Web, TCPBuffer, TCPBUFFER_SIZE, NULL);

        if (ParcelTCP_Size == -1) {
            MsgPrint("Response timeout expired from " + std::get<0>(HostPort) + "(" + IPHost + ")");
            break;
        }
        if (send(Host_Proxy, TCPBuffer, ParcelTCP_Size, NULL) != ParcelTCP_Size) {
            MsgPrint("Error sending response to Host");
            break;
        }
    } while (ParcelTCP_Size != 0);

    shutdown(Host_Proxy, SHUT_WR);
    shutdown(Proxy_Web, SHUT_RDWR);
    close(Host_Proxy);
    close(Proxy_Web);
    delete[] TCPBuffer;
    MsgPrint("Data exchange with " + std::get<0>(HostPort) + "(" + IPHost + ")" + " completed!");
}

void MsgPrint(std::string msg)
{
    std::time_t TimeNow = std::time(NULL);
    std::tm Time = *std::localtime(&TimeNow);
    char TimeData[20];
    strftime(TimeData, sizeof(TimeData), "%d-%m-%Y %X", &Time);
    PrintMtx.lock();
    printf("[%s] %s\n", TimeData, msg.c_str());
    PrintMtx.unlock();
}

std::tuple<std::string, unsigned short> ParsingTCP(std::string httpRequest)
{
    std::smatch result;
    std::regex regular("Host: "              // [0] строка с указанным началом
                        "((([\\w-\.]+.\\w+)" // [1] анализируемые строки
                        ":"                  // [2] анализируемые строки
                        "(\\d{1,5}))"        // [3] имя хоста с портом
                        "|"                  // [4] порт, если имеется
                        "([\\w-\.]+.\\w+))"  // [5] имя хоста без порта
                        "\\s+");             // пробельный символ (окончание)

    if (!std::regex_search(httpRequest, result, regular))   return std::make_tuple("0", 0);
    if (!((std::string)result[5]).empty())  return std::make_tuple(result[5], DEFAULT_HTTP_PORT);
    else                                    return std::make_tuple(result[3], stoi(result[4]));
}

bool BlackRules(std::string _Host, std::string _IP)
{
    _Host = (_Host.find("www.") != -1) ? _Host.substr(4) : _Host;
    std::string row;
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(ConnDB, "SELECT URL FROM BlackURLs;", -1, &stmt, NULL);
    while (sqlite3_step(stmt) != SQLITE_DONE) {
        row = (char*)sqlite3_column_text(stmt, 0);
        if (_Host.find(row) != -1) return false;
    }
    sqlite3_prepare_v2(ConnDB, "SELECT IP FROM BlackIP;", -1, &stmt, NULL);
    while (sqlite3_step(stmt) != SQLITE_DONE) {
        row = (char*)sqlite3_column_text(stmt, 0);
        if (_IP == row) return false;
    }
    return true;
}

bool WhiteRules(std::string _Host, std::string _IP)
{
    _Host = (_Host.find("www.") != -1) ? _Host.substr(4) : _Host;
    std::string row;
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(ConnDB, "SELECT URL FROM WhiteURLs;", -1, &stmt, NULL);
    while (sqlite3_step(stmt) != SQLITE_DONE) {
        row = (char*)sqlite3_column_text(stmt, 0);
        if (_Host.find(row) != -1) return true;
    }
    sqlite3_prepare_v2(ConnDB, "SELECT IP FROM WhiteIP;", -1, &stmt, NULL);
    while (sqlite3_step(stmt) != SQLITE_DONE) {
        row = (char*)sqlite3_column_text(stmt, 0);
        if (_IP == row) return true;
    }
    return false;
}

void AddingRecord(int Socket, std::string httpRequest)
{
    std::string Query;
    if (httpRequest.find("\r\n\r\nURL=") != -1) {
        Query = "BEGIN TRANSACTION; Insert into " + (WhiteBlackListMode ? (std::string)"WhiteURLs" : (std::string)"BlackURLs") +
            "(URL) values('" + httpRequest.substr(httpRequest.rfind("=")).erase(0, 1) + "'); COMMIT;";
        if (sqlite3_exec(ConnDB, Query.c_str(), NULL, NULL, NULL) == SQLITE_OK)
            MsgPrint("URL added to rule");
    }
    else if (httpRequest.find("\r\n\r\nIP=") != -1) {
        Query = "BEGIN TRANSACTION; Insert into " + (WhiteBlackListMode ? (std::string)"WhiteIP" : (std::string)"BlackIP") +
            "(IP) values('" + httpRequest.substr(httpRequest.rfind("=")).erase(0, 1) + "'); COMMIT;";
        if (sqlite3_exec(ConnDB, Query.c_str(), NULL, NULL, NULL) == SQLITE_OK)
            MsgPrint("IP added to rule");
    }
    Redirect(Socket);
}

void DeletingRecord(int Socket, std::string httpRequest)
{
    std::string Query;
    if (httpRequest.find("\r\n\r\nURL=") != -1) {
        Query = "BEGIN TRANSACTION; Delete from " + (WhiteBlackListMode ? (std::string)"WhiteURLs" : (std::string)"BlackURLs") +
            " where URL='" + httpRequest.substr(httpRequest.rfind("=")).erase(0, 1) + "'; COMMIT;";
        if (sqlite3_exec(ConnDB, Query.c_str(), NULL, NULL, NULL) == SQLITE_OK)
            MsgPrint("URL deleted from rule");
    }
    else if (httpRequest.find("\r\n\r\nIP=") != -1) {
        Query = "BEGIN TRANSACTION; Delete from " + (WhiteBlackListMode ? (std::string)"WhiteIP" : (std::string)"BlackIP") +
            " where IP='" + httpRequest.substr(httpRequest.rfind("=")).erase(0, 1) + "'; COMMIT;";
        if (sqlite3_exec(ConnDB, Query.c_str(), NULL, NULL, NULL) == SQLITE_OK)
            MsgPrint("IP deleted from rule");
    }
    Redirect(Socket);
}

void AdminPanelHandler(std::string ip, int port)
{
    int New_connection;
    int ADMIN_PANEL = socket(AF_INET, SOCK_STREAM, NULL);
    sockaddr_in ADMIN_PANEL_SOCKADDR;
    ADMIN_PANEL_SOCKADDR.sin_addr.s_addr = inet_addr(ip.c_str());
    ADMIN_PANEL_SOCKADDR.sin_port = htons(port);
    ADMIN_PANEL_SOCKADDR.sin_family = AF_INET;
    unsigned int SIZE_OF_ADDR = sizeof(ADMIN_PANEL_SOCKADDR);

    bind(ADMIN_PANEL, (sockaddr*)&ADMIN_PANEL_SOCKADDR, sizeof(ADMIN_PANEL_SOCKADDR));
    listen(ADMIN_PANEL, 10);
    MsgPrint("Admin Panel loaded on " + (std::string)ip + ":" + std::to_string(port));

    while (1) {
        New_connection = accept(ADMIN_PANEL, (sockaddr*)&ADMIN_PANEL_SOCKADDR, &SIZE_OF_ADDR);
        Conrtoller(New_connection);
    }

    close(New_connection);
    close(ADMIN_PANEL);
}

void Conrtoller(int Host_AdmPnl)
{
    char* TCPBuffer = new char[TCPBUFFER_SIZE] {};
    int ParcelTCP_Size = recv(Host_AdmPnl, TCPBuffer, TCPBUFFER_SIZE, NULL);

    if (((std::string)TCPBuffer).find("POST /Deleting HTTP") != -1)      DeletingRecord(Host_AdmPnl, TCPBuffer);
    else if (((std::string)TCPBuffer).find("POST /Adding HTTP") != -1)   AddingRecord(Host_AdmPnl, TCPBuffer);
    else if (((std::string)TCPBuffer).find("GET / HTTP") != -1)          ResponseOnGET(Host_AdmPnl);

    close(Host_AdmPnl);
    delete[] TCPBuffer;
}

void ResponseOnGET(int Socket)
{
    MsgPrint("Request for Admin Panel received");
    std::string HTML, trHTML1, trHTML2, selectHTML1, selectHTML2, Query; short NRow = 1, index;
    sqlite3_stmt* stmt;
    std::ifstream inputHTML("./Resources/MainShell.html");
    std::stringstream strStream;
    strStream << inputHTML.rdbuf();
    HTML = strStream.str();
    inputHTML.close();
    Query = "SELECT URL FROM " + (WhiteBlackListMode ? (std::string)"WhiteURLs" : (std::string)"BlackURLs");
    sqlite3_prepare_v2(ConnDB, Query.c_str(), -1, &stmt, NULL);
    while (sqlite3_step(stmt) != SQLITE_DONE) {
        selectHTML1 += "<option>" + std::string((char*)sqlite3_column_text(stmt, 0)) + "</option>";
        trHTML1 += "<tr><td>" + std::to_string(NRow) + "</td><td>" + (char*)sqlite3_column_text(stmt, 0) + "</td></tr>";
        NRow++;
    }
    NRow = 1;
    Query = "SELECT IP FROM " + (WhiteBlackListMode ? (std::string)"WhiteIP" : (std::string)"BlackIP");
    sqlite3_prepare_v2(ConnDB, Query.c_str(), -1, &stmt, NULL);
    while (sqlite3_step(stmt) != SQLITE_DONE) {
        selectHTML2 += "<option>" + std::string((char*)sqlite3_column_text(stmt, 0)) + "</option>";
        trHTML2 += "<tr><td>" + std::to_string(NRow) + "</td><td>" + (char*)sqlite3_column_text(stmt, 0) + "</td></tr>";
        NRow++;
    }
    index = HTML.find("%");
    HTML = HTML.erase(index, 1).insert(index, WhiteBlackListMode ? (std::string)"WhiteList" : (std::string)"BlackList");
    index = HTML.find("%");
    HTML = HTML.erase(index, 1).insert(index, selectHTML1);
    index = HTML.find("%");
    HTML = HTML.erase(index, 1).insert(index, selectHTML2);
    index = HTML.find("%");
    HTML = HTML.erase(index, 1).insert(index, trHTML1);
    index = HTML.find("%");
    HTML = HTML.erase(index, 1).insert(index, trHTML2);

    std::string httpResponse = "HTTP/1.1 200 OK\n"
                               "Content-type: text/html\n"
                               "Content-Length:" + std::to_string(HTML.length()) + "\n\n" + HTML;
    send(Socket, httpResponse.c_str(), httpResponse.size(), NULL);
}

void Response403(int _Host_Proxy)
{
    std::ifstream inputHTML("./Resources/Response403.html");
    std::stringstream strStream;
    strStream << inputHTML.rdbuf();
    std::string HTML = strStream.str();
    inputHTML.close();

    std::string httpResponse = "HTTP/1.1 403 Forbidden\n"
                               "Content-type: text/html\n"
                               "Content-Length:" + std::to_string(HTML.length()) + "\n\n" + HTML;
    send(_Host_Proxy, httpResponse.c_str(), httpResponse.size(), NULL);
}

void Redirect(int Socket)
{
    std::ifstream inputHTML("./Resources/Redirect.html");
    std::stringstream strStream;
    strStream << inputHTML.rdbuf();
    std::string HTML = strStream.str();
    inputHTML.close();

    std::string httpResponse =  "HTTP/1.1 200 OK\n"
                                "Content-type: text/html\n"
                                "Content-Length:" + std::to_string(HTML.length()) + "\n\n" + HTML;
    send(Socket, httpResponse.c_str(), httpResponse.size(), NULL);
}
