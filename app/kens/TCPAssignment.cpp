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
map<socket_data::StatusKey, socket_data::StatusVar> SocketStatusMap;

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

  SocketStatusMap[make_pair(socketfd, pid)] = socket_data::ClosedStatus{syscallUUID, pid}; 

  return socketfd;
}

int TCPAssignment::syscall_close(UUID syscallUUID, int pid, int sockfd){
  removeFileDescriptor(pid, sockfd);
  
  if (SocketStatusMap.erase(make_pair(sockfd, pid))){
    return 0;
  }

  return -1;
}

int TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int sockfd, struct sockaddr * addr, socklen_t addrlen){
  struct socket_data::ClosedStatus* currClosedSocket = get_if<socket_data::ClosedStatus>(&SocketStatusMap.find(make_pair(sockfd, pid))->second);
  if (currClosedSocket == nullptr) return -1;

  in_addr_t server_ip = ((sockaddr_in *)addr)->sin_addr.s_addr;
  uint16_t server_port = ((sockaddr_in *)addr)->sin_port;

  // Server 에 Packet 만들어서 보내주기

  // Status Change Listen -> SysSent
  
  MyPacket fstPacket((size_t)54);
  ipv4_t server_address_array = NetworkUtil::UINT64ToArray<4> (server_ip);
  uint16_t client_port = getRoutingTable(server_address_array);
  std::optional<ipv4_t> client_address_array = getIPAddr(client_port);
  uint16_t client_ip = NetworkUtil::arrayToUINT64(client_address_array.value());
  
  int SeqNnum = 1;

  fstPacket.IPAddrWrite(client_ip,server_ip);
  fstPacket.TCPHeadWrite(client_ip ,server_ip ,9999,server_port,SeqNnum,2,0b10);

  sendPacket("IPv4", std::move(fstPacket.pkt));

  uint32_t buf1 = fstPacket.ACKNum();
  uint32_t buf2 =fstPacket.SeqNum();
  uint16_t buf3 = fstPacket.dest_port();
  uint16_t buf4 = fstPacket.source_port();
  uint32_t buf5 = fstPacket.source_ip();
  uint32_t buf6 = fstPacket.dest_ip();

  uint16_t buff = fstPacket.flag();
  return 0;
}

int TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog){
  struct socket_data::BindStatus* currBindedSocket = get_if<socket_data::BindStatus>(&SocketStatusMap.find(make_pair(sockfd, pid))->second);
  if (currBindedSocket == nullptr) return -1;

  SocketStatusMap[make_pair(sockfd, pid)] = socket_data::ListeningStatus{syscallUUID, pid, currBindedSocket->address, currBindedSocket->port, backlog};

  return 0;
}

int TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr * addr, socklen_t * addrlen){
  struct socket_data::ListeningStatus* currListeningSocket = get_if<socket_data::ListeningStatus>(&SocketStatusMap.find(make_pair(sockfd, pid))->second);
  if (currListeningSocket == nullptr) return -1;

  Packet& packet = currListeningSocket->packetQueue.front();
  currListeningSocket->packetQueue.pop();
  // packet 정보 받아오기

  // addr에 Client 정보 넣어주기

  // 2번째 Packet client 쪽에 보내주기

  // Status Change Listen -> SynRcvd
  
  return 0;
}

int TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr * addr, socklen_t addrlen){
  in_addr_t s_addr = ((sockaddr_in *)addr)->sin_addr.s_addr;
  uint16_t port = ((sockaddr_in *)addr)->sin_port;

  // sockfd에 bind 된 socket이 있을 때
  if (SocketStatusMap.find(make_pair(sockfd, pid)) != SocketStatusMap.end()){
    // Closed 된 소켓 (Open 되어 있는) 있는지 확인 - 있어야 함
    struct socket_data::ClosedStatus* currClosedSocket = get_if<socket_data::ClosedStatus>(&SocketStatusMap.find(make_pair(sockfd, pid))->second);
    if (currClosedSocket == nullptr) return -1;

    // sockfd에 이미 bind 된 애가 있을 때 있는지 확인 - 있으면 안되
    struct socket_data::BindStatus* currBindSocket = get_if<socket_data::BindStatus>(&SocketStatusMap.find(make_pair(sockfd, pid))->second);
    if (currBindSocket != nullptr) return -1;

    // Binded 된 소켓 중 port 가 중복된 것이 있는지 확인
    for(auto iter = SocketStatusMap.begin(); iter != SocketStatusMap.end(); iter++){
      socket_data::StatusKey statuskey = iter->first;
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
    SocketStatusMap[make_pair(sockfd, pid)] = socket_data::BindStatus{syscallUUID, pid, s_addr, port};

    return 0;
  }
  else{
    return -1;
  }
  return 0;
  
}

int TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr * addr, socklen_t * addrlen){ //  TODO : addrlen 에 맞춰 짜르기 구현
  struct socket_data::BindStatus* currBindSocket = get_if<socket_data::BindStatus>(&SocketStatusMap.find(make_pair(sockfd, pid))->second);
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
  // 온 Packet 정보 받아오기
  socket_data::StatusVar sock_status_data;
  in_addr_t senders_destination_ip;
  uint16_t port;

  for(auto iter = SocketStatusMap.begin(); iter != SocketStatusMap.end(); iter++){
      socket_data::SocketFD socketfd = get<0, socket_data::SocketFD>(iter->first);
      socket_data::ProcessID processid = get<1, socket_data::ProcessID>(iter->first);
      socket_data::StatusVar& currsock = iter->second;
      struct socket_data::ListeningStatus* currListeningsock = get_if<socket_data::ListeningStatus>(&currsock);
      if (currListeningsock != nullptr) continue;

      if(currListeningsock->address == INADDR_ANY && currListeningsock->port == port || 
      currListeningsock->address == senders_destination_ip && currListeningsock->port == port){
        UUID uuid = currListeningsock->syscallUUID;
        int processid = currListeningsock->processid;

        int socketfd = createFileDescriptor(processid);
        SocketStatusMap[make_pair(socketfd, processid)] = socket_data::SynRcvdStatus{uuid, processid};
      }
    }

  visit(overloaded{
    [&](socket_data::ListeningStatus sock_data) {
      // Client -> Server
      // Listening queue에 넣어주기

      
    },
    [&](socket_data::SysSentStatus sock_data) {
      // Server -> Client
      // SYNbit, Seq 넘버 확인.
      
      
      // Make New Socket Data Status: ESTAB

    },
    [&](socket_data::SynRcvdStatus sock_data) {
      // Client -> Server
      // ACKbit, ACKnum 확인. ESTAB


      // Status Change SysSent -> ESTAB

    },
    [](auto sock_data) {
      // 위의 상태와 다른 경우. 에러처리

    },
  }, sock_status_data);
}

void TCPAssignment::timerCallback(any payload) {
  
}

void MyPacket::IPAddrWrite(in_addr_t s_addr, in_addr_t d_addr) {
  pkt.writeData((size_t)26, &s_addr, (size_t)4);
  pkt.writeData((size_t)30, &d_addr, (size_t)4);
}

void MyPacket::TCPHeadWrite(uint32_t source_ip, uint32_t dest_ip, 
    uint16_t source_port, uint16_t dest_port, uint32_t SeqNum, uint32_t ACKNum, uint16_t flag) {
  this->pkt.writeData((size_t)34, &source_port, (size_t)2);
  this->pkt.writeData((size_t)36, &dest_port, (size_t)2);
  this->pkt.writeData((size_t)38, &SeqNum, (size_t)4);
  this->pkt.writeData((size_t)42, &ACKNum, (size_t)4);

  flag = (0b0101<<12) +flag;
  this->pkt.writeData((size_t)46, &flag, (size_t)2);
  uint8_t buffer[1000];
  this->pkt.readData(34,buffer,20);
  uint16_t checkSum = NetworkUtil::tcp_sum(source_ip,dest_ip, buffer, 20);
  this->pkt.writeData((size_t)50, &checkSum, (size_t)2);
}

in_addr_t MyPacket::source_ip() {
  in_addr_t ret;
  this->pkt.readData((size_t)26,&ret, (size_t)4);
  return ret;
}

in_addr_t MyPacket::dest_ip() {
  in_addr_t ret;
  this->pkt.readData((size_t)30,&ret, (size_t)4);
  return ret;
}

uint16_t MyPacket::source_port() {
  uint16_t ret;
  this->pkt.readData((size_t)34, &ret, (size_t)2);
  return ret;
}

uint16_t MyPacket::dest_port() {
  uint16_t ret;
  this->pkt.readData((size_t)36, &ret, (size_t)2);
  return ret;
}

uint32_t MyPacket::SeqNum() {
  uint32_t ret;
  this->pkt.readData((size_t)38, &ret, (size_t)4);
  return ret;
}

uint32_t MyPacket::ACKNum() {
  uint32_t ret;
  this->pkt.readData((size_t)42, &ret, (size_t)4);
  return ret;
}

uint8_t MyPacket::flag() {
  uint8_t ret;
  this->pkt.readData((size_t)46, &ret, (size_t)2);

  return ret;
}

} // namespace E

