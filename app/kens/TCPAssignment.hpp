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

class MyPacket {
private:
  size_t size;

public:
  Packet pkt;
  MyPacket(size_t in_size): pkt{Packet(in_size)}, size{in_size} {}
  MyPacket(Packet packet): pkt{packet} {}
  void IPAddrWrite(in_addr_t s_addr, in_addr_t d_addr);
  void TCPHeadWrite(uint32_t source_ip, uint32_t dest_ip, uint16_t source_port, uint16_t dest_port, uint32_t SeqNum, uint32_t AckNum, uint16_t flag); 
  in_addr_t source_ip();
  in_addr_t dest_ip();
  uint16_t source_port();
  uint16_t dest_port();
  uint32_t SeqNum();
  uint32_t ACKNum();
  uint16_t flag(); 
  void SeqNumAdd(int n);
  void ACKNumAdd(int n);
};

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
    int queueMaxLen;
    queue<Packet> packetQueue;
    ListeningStatus(UUID uuid, int pid, in_addr_t addr, uint16_t p, int len): syscallUUID{uuid}, processid{pid}, address{addr}, port{p}, queueMaxLen{len} {};
    //ListeningStatus() : ListeningStatus(-1, -1, 0, 0) {}
  };

  struct SysSentStatus{
    UUID syscallUUID;
    int processid;
    in_addr_t serveraddress;
    uint16_t serverport;
    in_addr_t myaddress;
    uint16_t myport;
    SysSentStatus(UUID uuid, int pid, in_addr_t saddr, uint16_t sp, in_addr_t caddr, uint16_t cp): syscallUUID{uuid}, processid{pid}, serveraddress{saddr}, serverport{sp}, myaddress{caddr}, myport{cp} {};
  };

  struct SynRcvdStatus{
    UUID syscallUUID;
    int processid;
    in_addr_t address;
    uint16_t port;
    SynRcvdStatus(UUID uuid, int pid): syscallUUID{uuid}, processid{pid} {};
  };

  struct EstabStatus{
    UUID syscallUUID;
    int processid;
    in_addr_t serverAddress;
    uint16_t serverPort;
    EstabStatus(UUID uuid, int pid): syscallUUID{uuid}, processid{pid} {};
  };

  using StatusVar = variant<ClosedStatus, BindStatus, ListeningStatus, SysSentStatus, SynRcvdStatus, EstabStatus>;
  using ProcessID = int;
  using SocketFD = int;
  using StatusKey = pair<SocketFD, ProcessID>;
};

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
