#include "EchoAssignment.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <arpa/inet.h>

// !IMPORTANT: allowed system calls.
// !DO NOT USE OTHER NETWORK SYSCALLS (send, recv, select, poll, epoll, fork
// etc.)
//  * socket
//  * bind
//  * listen
//  * accept
//  * read
//  * write
//  * close
//  * getsockname
//  * getpeername
// See below for their usage.
// https://github.com/ANLAB-KAIST/KENSv3/wiki/Misc:-External-Resources#linux-manuals

int EchoAssignment::serverMain(const char *bind_ip, int port,
                               const char *server_hello) {
  // Your server code
  // !IMPORTANT: do not use global variables and do not define/use functions
  // !IMPORTANT: for all system calls, when an error happens, your program must
  // return. e.g., if an read() call return -1, return -1 for serverMain.

  int sockfd;
  if ((sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == 0){
    //error
    perror("Failed : socket\n");
    exit(0);
  }

  struct sockaddr_in serveraddr;
  memset(&serveraddr, 0, sizeof(serveraddr));

  serveraddr.sin_family = AF_INET;
  serveraddr.sin_addr.s_addr = htonl(inet_addr(bind_ip));
  serveraddr.sin_port = htons(port);

  if (bind(sockfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) != 0){
    perror("Failed : bind\n");
    exit(0);
  }

  if (listen(sockfd, 10) != 0){
    perror("Failed : listen\n");
    exit(0);
  }

  int client_sockfd;
  struct sockaddr_in clientaddr;
  socklen_t sizeof_clientaddr = (socklen_t) sizeof(clientaddr);

  while(1){
    client_sockfd = accept(sockfd, (struct sockaddr *) &clientaddr, &sizeof_clientaddr);

    if(client_sockfd != -1){
      submitAnswer("10.0.0.2", "accept Success");
    }
    else{
      perror("Failed : accept\n");
      exit(0);
    }
  }

  close(sockfd);
  return 0;
}

int EchoAssignment::clientMain(const char *server_ip, int port,
                               const char *command) {
  // Your client code
  // !IMPORTANT: do not use global variables and do not define/use functions
  // !IMPORTANT: for all system calls, when an error happens, your program must
  // return. e.g., if an read() call return -1, return -1 for clientMain.

  int clientfd;
  if ((clientfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == 0){
    //error
    perror("Failed : socket\n");
    exit(0);
  }

  struct sockaddr_in serveraddr;

  serveraddr.sin_family = AF_INET;
  serveraddr.sin_addr.s_addr=inet_addr(server_ip);
  serveraddr.sin_port = htons(port);

  if (connect(clientfd, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) == -1){
    perror("Failed : connect \n");
    exit(0);
  }

  return 0;
}

static void print_usage(const char *program) {
  printf("Usage: %s <mode> <ip-address> <port-number> <command/server-hello>\n"
         "Modes:\n  c: client\n  s: server\n"
         "Client commands:\n"
         "  hello : server returns <server-hello>\n"
         "  whoami: server returns <client-ip>\n"
         "  whoru : server returns <server-ip>\n"
         "  others: server echos\n"
         "Note: each command is terminated by newline character (\\n)\n"
         "Examples:\n"
         "  server: %s s 0.0.0.0 9000 hello-client\n"
         "  client: %s c 127.0.0.1 9000 whoami\n",
         program, program, program);
}

int EchoAssignment::Main(int argc, char *argv[]) {

  if (argc == 0)
    return 1;

  if (argc != 5) {
    print_usage(argv[0]);
    return 1;
  }

  int port = atoi(argv[3]);
  if (port == 0) {
    printf("Wrong port number\n");
    print_usage(argv[0]);
  }

  switch (*argv[1]) {
  case 'c':
    return clientMain(argv[2], port, argv[4]);
  case 's':
    return serverMain(argv[2], port, argv[4]);
  default:
    print_usage(argv[0]);
    return 1;
  }
}
