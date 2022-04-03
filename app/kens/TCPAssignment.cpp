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

namespace E {

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

  switch (param.syscallNumber) {
  case SOCKET:
    //2번째 인자 추가함
     this->syscall_socket(syscallUUID, pid, std::get<int>(param.params[0]),
            std::get<int>(param.params[1]), std::get<int>(param.params[2]));
    break;
  case CLOSE:
     this->syscall_close(syscallUUID, pid, std::get<int>(param.params[0]));
    break;
  case READ:
    // this->syscall_read(syscallUUID, pid, std::get<int>(param.params[0]),
    //                    std::get<void *>(param.params[1]),
    //                    std::get<int>(param.params[2]));
    break;
  case WRITE:
    // this->syscall_write(syscallUUID, pid, std::get<int>(param.params[0]),
    //                     std::get<void *>(param.params[1]),
    //                     std::get<int>(param.params[2]));
    break;
  case CONNECT:
     this->syscall_connect(
         syscallUUID, pid, std::get<int>(param.params[0]),
         static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
         (socklen_t)std::get<int>(param.params[2]));
    break;
  case LISTEN:
     this->syscall_listen(syscallUUID, pid, std::get<int>(param.params[0]),
                          std::get<int>(param.params[1]));
    break;
  case ACCEPT:
     this->syscall_accept(
         syscallUUID, pid, std::get<int>(param.params[0]),
         static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
         static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    break;
  case BIND:
     this->syscall_bind(
         syscallUUID, pid, std::get<int>(param.params[0]),
         static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
         (socklen_t)std::get<int>(param.params[2]));
    break;
  case GETSOCKNAME:
     this->syscall_getsockname(
         syscallUUID, pid, std::get<int>(param.params[0]),
         static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
         static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    break;
  case GETPEERNAME:
     this->syscall_getpeername(
         syscallUUID, pid, std::get<int>(param.params[0]),
         static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
         static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    break;
  default:
    assert(0);
  }
}

int TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int type, int protocol){
  return 1;
}

int TCPAssignment::syscall_close(UUID syscallUUID, int pid, int domain){
  return 1;
}

int TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int sockfd, struct sockaddr * addr, socklen_t addrlen){
  return 1;
}

int TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog){
  return 1;
}

int TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr * addr, socklen_t * addrlen){
  return 1;
}

int TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr * addr, socklen_t addrlen){
  return 1;
}

int TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr * addr, socklen_t * addrlen){
  return 1;
}

int TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr * addr, socklen_t * addrlen){
  return 1;
}


void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  // Remove below
  (void)fromModule;
  (void)packet;
}

void TCPAssignment::timerCallback(std::any payload) {
  // Remove below
  (void)payload;
}

} // namespace E
