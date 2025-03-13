#include "../include/starter.h"
#include <arpa/inet.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define MANAGER_LISTEN_PORT 8090
#define BUFSIZE 1024
#define LISTEN_SIZE 5
#define PACKET_LENGTH 6
#define START_SERVER 0x14
#define STOP_SERVER 0x15
#define MSG_SIZE 256
#define ONLINE 0x0C
#define VERSION 0x01
#define SENDER 0x00
#define OFFSET 0xFF
#define MOVE_EIGHT 8
#define MOVE_TWO 2
#define PAYLOAD_LEN 4

int           createSocket(void);
noreturn void listenForCommand(int sockfd, int *server_pid);
void          parsePacket(const char *buffer, ssize_t length, int *server_pid);
int           launchServer(void);
void          notifyServerManager(const char *manager_ip, int manager_port, const char *server_port);

int createSocket(void)
{
    int                sockfd;
    struct sockaddr_in address;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd == -1)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family      = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port        = htons(MANAGER_LISTEN_PORT);

    if(bind(sockfd, (struct sockaddr *)&address, sizeof(address)) == -1)
    {
        perror("bind failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    return sockfd;
}

void listenForCommand(int sockfd, int *server_pid)
{
    struct sockaddr_in manageraddr;
    socklen_t          manageraddr_len = sizeof(manageraddr);

    if(listen(sockfd, LISTEN_SIZE) < 0)
    {
        perror("listen faied");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("listening on port %d\n", MANAGER_LISTEN_PORT);

    while(1)
    {
        int     managerfd;
        char    buffer[BUFSIZE];
        ssize_t bytesReceived;

        managerfd = accept(sockfd, (struct sockaddr *)&manageraddr, &manageraddr_len);
        if(managerfd == -1)
        {
            perror("accept failed");
            continue;
        }

        printf("connected to manager\n");

        bytesReceived = read(managerfd, buffer, BUFSIZE);
        if(bytesReceived > 0)
        {
            parsePacket(buffer, bytesReceived, server_pid);
        }
        else
        {
            perror("read failed");
        }

        close(managerfd);
    }
}

int launchServer(void)
{
    int  server_pid;
    char cwd[PATH_MAX];
    getcwd(cwd, sizeof(cwd));    // this is for the workign directory

    printf("launching server from: %s\n", cwd);
    printf("check if ./server exists\n");

    if(access("./server", X_OK) != 0)    // check if the server exists
    {
        perror("error suerver not found");
        exit(EXIT_FAILURE);
    }

    server_pid = fork();
    if(server_pid == 0)
    {
        execl("./server", "-a", "127.0.0.1", "-p", "8080", NULL);

        perror("exec failed");
        exit(EXIT_FAILURE);
    }
    else if(server_pid < 0)
    {
        perror("fork failed");
    }
    else
    {
        printf("server started with pid = %d\n", server_pid);
        sleep(1);
        signal(SIGCHLD, SIG_IGN);
        return server_pid;
    }
    return 0;
}

void parsePacket(const char *buffer, ssize_t length, int *server_pid)
{
    char           packetType;
    char           version;
    unsigned short senderId;
    unsigned short payload_len;

    if(length < PACKET_LENGTH)
    {
        return;
    }

    packetType = buffer[0];
    version    = buffer[1];

    memcpy(&senderId, buffer + MOVE_TWO, sizeof(senderId));
    senderId = ntohs(senderId);

    memcpy(&payload_len, buffer + PAYLOAD_LEN, sizeof(payload_len));
    payload_len = ntohs(payload_len);

    printf("packet type =  %02X, version = %d, sender id = %d, payload length =  %d\n", (unsigned int)packetType, version, senderId, payload_len);

    if(packetType == START_SERVER)
    {
        printf("received start command. server is starting\n");
        *server_pid = launchServer();
        notifyServerManager("127.0.0.1", MANAGER_LISTEN_PORT, "8081");    // Adjust manager IP and port accordingly
    }
    else if(packetType == STOP_SERVER)
    {
        printf("received stop command. ending server\n");
        if(*server_pid > 0)
        {
            kill(*server_pid, SIGTERM);
            printf("server with pid %d stopped\n", *server_pid);
            *server_pid = -1;    // Reset PID after stopping
        }
        else
        {
            printf("there is no server running.\n");
        }
    }
    else
    {
        printf("received unknown command\n");
    }
}

void notifyServerManager(const char *manager_ip, int manager_port, const char *server_port)
{
    int                manager_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in manager_addr;
    unsigned char      msg[MSG_SIZE];
    int                offset;
    unsigned char      payload_len;
    size_t             port_len;

    manager_addr.sin_family = AF_INET;
    manager_addr.sin_port   = htons((uint16_t)manager_port);
    inet_pton(AF_INET, manager_ip, &manager_addr.sin_addr);

    if(manager_sock == -1)
    {
        perror("socket failed");
        return;
    }

    if(connect(manager_sock, (struct sockaddr *)&manager_addr, sizeof(manager_addr)) < 0)
    {
        perror("connect failed");
        close(manager_sock);
        return;
    }

    offset   = 0;
    port_len = strlen(server_port);

    msg[offset++] = ONLINE;     // online
    msg[offset++] = VERSION;    // version
    msg[offset++] = SENDER;     // sender id
    msg[offset++] = SENDER;     // sender id

    payload_len   = (unsigned char)(port_len + MOVE_TWO);
    msg[offset++] = (unsigned char)((payload_len >> MOVE_EIGHT) & OFFSET);
    msg[offset++] = payload_len & OFFSET;

    msg[offset++] = ONLINE;
    msg[offset++] = (unsigned char)port_len;
    memcpy(&msg[offset], server_port, port_len);
    offset += (int)port_len;

    send(manager_sock, msg, (size_t)offset, 0);
    printf("SVR_Online sent to manager.\n");

    close(manager_sock);
}

int main(void)
{
    int server_pid = -1;
    int listenfd   = createSocket();
    listenForCommand(listenfd, &server_pid);
}
