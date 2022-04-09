/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_

#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_TimerModule.hpp>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

using namespace std;

namespace E {

//NotImplemented Yet (Status with Variant)

class socket_data{
public:
  struct ClosedStatus{
    UUID syscallUUID;
    int processid;
    ClosedStatus(UUID uuid, int pid): syscallUUID{uuid}, processid{pid}{};
    ClosedStatus(): ClosedStatus(-1, -1) {}
  };

  struct BindStatus{
    UUID syscallUUID; 
    int processid;
    in_addr_t address;
    uint16_t port;
    BindStatus(UUID uuid, int pid, in_addr_t addr, uint16_t p): syscallUUID{uuid}, processid{pid},address{addr}, port{p} {};
    //BindStatus() : BindStatus(-1, -1, 0, 0) {}
  };

  struct ListeningStatus{
    UUID syscallUUID;
    int processid;
    in_addr_t address;
    uint16_t port;
    ListeningStatus(UUID uuid, int pid, in_addr_t addr, uint16_t p): syscallUUID{uuid}, processid{pid},address{addr},port{p} {};
    //ListeningStatus() : ListeningStatus(-1, -1, 0, 0) {}
  };

  using StatusVar = variant<ClosedStatus, BindStatus, ListeningStatus>;
};

//NotImplemented Yet (Status with Variant)

class TCPAssignment : public HostModule,
                      private RoutingInfoInterface,
                      public SystemCallInterface,
                      public TimerModule {
private:
  virtual void timerCallback(std::any payload) final;

public:
  TCPAssignment(Host &host);
  virtual void initialize();
  virtual void finalize();
  virtual ~TCPAssignment();

protected:
  virtual void systemCallback(UUID syscallUUID, int pid,
                              const SystemCallParameter &param) final;
  virtual void packetArrived(std::string fromModule, Packet &&packet) final;

private:
  int syscall_socket(UUID syscallUUID, int pid, int domain, int type, int protocol);
  int syscall_close(UUID syscallUUID, int pid, int sockfd);
  int syscall_connect(UUID syscallUUID, int pid, int sockfd, struct sockaddr * addr, socklen_t addrlen);
  int syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog);
  int syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr * addr, socklen_t * addrlen);
  int syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr * addr, socklen_t addrlen);
  int syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr * addr, socklen_t * addrlen);
  int syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr * addr, socklen_t * addrlen);
};

class TCPAssignmentProvider {
private:
  TCPAssignmentProvider() {}
  ~TCPAssignmentProvider() {}

public:
  static void allocate(Host &host) { host.addHostModule<TCPAssignment>(host); }
};

} // namespace E

#endif /* E_TCPASSIGNMENT_HPP_ */
