/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#include "TCPAssignment.hpp"
#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Packet.hpp>
#include <cerrno>
#include <list>
#include <functional>

using namespace std;

namespace E {

// New Data Structure

// key : file descripter
map<int, socket_data::StatusVar> SocketStatusMap;

// Data Structure for Saving 
struct BindedPort{
  int pid;
  int fd;
  in_addr_t address;
  uint16_t port;
};

struct ListeningSocket{
  int backlog;
  struct BindedPort *bindedPort;
  queue<int> *waitingqueue;
};

list<BindedPort> bindedPortList;
list<ListeningSocket> listeningPortList;

TCPAssignment::TCPAssignment(Host &host)
    : HostModule("TCP", host), RoutingInfoInterface(host),
      SystemCallInterface(AF_INET, IPPROTO_TCP, host),
      TimerModule("TCP", host) {}

TCPAssignment::~TCPAssignment() {}

void TCPAssignment::initialize() {
  
}

void TCPAssignment::finalize() {}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid,
                                   const SystemCallParameter &param) {

  // Remove below
  //(void)syscallUUID;
  //(void)pid;
  int returnInt;

  switch (param.syscallNumber) {
  case SOCKET:
    //2번째 인자 추가함
    returnInt = this->syscall_socket(syscallUUID, pid, get<int>(param.params[0]),
            get<int>(param.params[1]), get<int>(param.params[2]));
    break;
  case CLOSE:
     returnInt = this->syscall_close(syscallUUID, pid, get<int>(param.params[0]));
    break;
  case READ:
    // this->syscall_read(syscallUUID, pid, get<int>(param.params[0]),
    //                    get<void *>(param.params[1]),
    //                    get<int>(param.params[2]));
    break;
  case WRITE:
    // this->syscall_write(syscallUUID, pid, get<int>(param.params[0]),
    //                     get<void *>(param.params[1]),
    //                     get<int>(param.params[2]));
    break;
  case CONNECT: {
     this->syscall_connect(
         syscallUUID, pid, get<int>(param.params[0]),
         static_cast<struct sockaddr *>(get<void *>(param.params[1])),
         (socklen_t)get<int>(param.params[2]));
    break;
  }
  case LISTEN:{
     this->syscall_listen(syscallUUID, pid, get<int>(param.params[0]),
                          get<int>(param.params[1]));
    break;
  }
  case ACCEPT:{

     this->syscall_accept(
         syscallUUID, pid, get<int>(param.params[0]),
         static_cast<struct sockaddr *>(get<void *>(param.params[1])),
         static_cast<socklen_t *>(get<void *>(param.params[2])));
    break;
  }
  case BIND:{

     returnInt = this->syscall_bind(
         syscallUUID, pid, get<int>(param.params[0]),
         static_cast<struct sockaddr *>(get<void *>(param.params[1])),
         (socklen_t)get<int>(param.params[2]));
    break;
  }
  case GETSOCKNAME:{

     returnInt = this->syscall_getsockname(
         syscallUUID, pid, get<int>(param.params[0]),
         static_cast<struct sockaddr *>(get<void *>(param.params[1])),
         static_cast<socklen_t *>(get<void *>(param.params[2])));
    break;
  }
  case GETPEERNAME:{

    printf("GETPEERNAME \n");
    returnInt = this->syscall_getpeername(
         syscallUUID, pid, get<int>(param.params[0]),
         static_cast<struct sockaddr *>(get<void *>(param.params[1])),
         static_cast<socklen_t *>(get<void *>(param.params[2])));
    break;
  }
    default:{
      assert(0);
    }
  }
  this->returnSystemCall(syscallUUID, returnInt);
}

int TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int type, int protocol){
  if (domain != AF_INET) printf("SYSCALL_SOCKET: domain != AF_INET\n");
  if (type != SOCK_STREAM) printf("SYSCALL_SOCKET: type != SOCK_STREAM\n");
  if (protocol != IPPROTO_TCP) printf("SYSCALL_SOCKET: protocol != IPPROTO_TCP\n");

  int socketfd = createFileDescriptor(pid);

  SocketStatusMap[socketfd] = socket_data::ClosedStatus{syscallUUID, pid}; 

  return socketfd;
}

bool isRemovable(struct BindedPort * bp, int sockfd, int pid){
  if (bp->fd == sockfd && bp->pid == pid)
    return true;
  return false;
}

int TCPAssignment::syscall_close(UUID syscallUUID, int pid, int sockfd){
  removeFileDescriptor(pid, sockfd);
  list<BindedPort>::iterator it;
  for(it = bindedPortList.begin(); it != bindedPortList.end(); ){
    if (((struct BindedPort)(*it)).fd == sockfd && ((struct BindedPort)(*it)).pid == pid){
      bindedPortList.erase(it++);
      return 0;
    }
  }
  return 1;
}

int TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int sockfd, struct sockaddr * addr, socklen_t addrlen){
  
  
  return 1;
}

int TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog){
  struct socket_data::BindStatus* currBindedSocket = get_if<socket_data::BindStatus>(&SocketStatusMap.find(sockfd)->second);
  if (currBindedSocket == nullptr) return -1;

  SocketStatusMap[sockfd] = socket_data::ListeningStatus{syscallUUID, pid, currBindedSocket->address, currBindedSocket->port, backlog};

  return 0;
}

int TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr * addr, socklen_t * addrlen){
  return 1;
}

int TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr * addr, socklen_t addrlen){
  in_addr_t s_addr = ((sockaddr_in *)addr)->sin_addr.s_addr;
  uint16_t port = ((sockaddr_in *)addr)->sin_port;

  // sockfd에 bind 된 socket이 있을 때
  if (SocketStatusMap.find(sockfd) != SocketStatusMap.end()){
    // Closed 된 소켓 (Open 되어 있는) 있는지 확인 - 있어야 함
    struct socket_data::ClosedStatus* currClosedSocket = get_if<socket_data::ClosedStatus>(&SocketStatusMap.find(sockfd)->second);
    if (currClosedSocket == nullptr) return -1;

    // sockfd에 이미 bind 된 애가 있을 때 있는지 확인 - 있으면 안되
    struct socket_data::BindStatus* currBindSocket = get_if<socket_data::BindStatus>(&SocketStatusMap.find(sockfd)->second);
    if (currBindSocket != nullptr) return -1;

    // Binded 된 소켓 중 port 가 중복된 것이 있는지 확인
    for(auto iter = SocketStatusMap.begin(); iter != SocketStatusMap.end(); iter++){
      int curr_pid = iter->first;
      socket_data::StatusVar& currsock = iter->second;
      struct socket_data::BindStatus* currbindedsock = get_if<socket_data::BindStatus>(&currsock);
      if (currbindedsock != nullptr){
        if(currbindedsock->processid != pid) continue;

        if(currbindedsock->address == INADDR_ANY && currbindedsock->port == port){
          return -1;
        }
        if(currbindedsock->address == s_addr && currbindedsock->port == port){
          return -1;
        }
      }
    }

    //SocketStatusMap.erase(sockfd);
    SocketStatusMap[sockfd] = socket_data::BindStatus{syscallUUID, pid, s_addr, port};

    return 0;
  }
  else{
    return -1;
  }
  return 0;
  
}

int TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr * addr, socklen_t * addrlen){ //  TODO : addrlen 에 맞춰 짜르기 구현
  struct socket_data::BindStatus* currBindSocket = get_if<socket_data::BindStatus>(&SocketStatusMap.find(sockfd)->second);
  if (currBindSocket == nullptr) return -1;

  ((sockaddr_in *)addr)->sin_addr.s_addr = currBindSocket->address;
  ((sockaddr_in *)addr)->sin_port = currBindSocket->port;
  ((sockaddr_in *)addr)->sin_family =AF_INET;

  return 0;
}

int TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr * addr, socklen_t * addrlen){
  return 1;
}


void TCPAssignment::packetArrived(string fromModule, Packet &&packet) {
  // Remove below
  //(void)fromModule;
  //(void)packet;
}

void TCPAssignment::timerCallback(any payload) {
  // Remove below
  //(void)payload;
}

} // namespace E
