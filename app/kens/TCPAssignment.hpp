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
public:
  Packet pkt;
  MyPacket(size_t in_size): pkt{Packet(in_size)} {}
  MyPacket(Packet packet): pkt{packet} {}
  void IPAddrWrite(in_addr_t s_addr, in_addr_t d_addr);
  void TCPHeadWrite(in_addr_t source_ip, in_addr_t dest_ip, uint16_t source_port, uint16_t dest_port, uint32_t SeqNum, uint32_t AckNum, uint16_t flag); 
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
  using SocketFD = int;
  using ProcessID = int;
  using StatusKey = pair<SocketFD, ProcessID>;
  using WaitingKey = pair<UUID,struct sockaddr *>;

  struct ClosedStatus{
    UUID syscallUUID;
    int processid;
    ClosedStatus(UUID uuid, int pid): syscallUUID{uuid}, processid{pid}{};
    ClosedStatus(): ClosedStatus(-1, -1) {}
  };

  struct BindStatus{
    UUID syscallUUID; 
    int processid;
    in_addr_t sourceip;
    uint16_t sourceport;
    BindStatus(UUID uuid, int pid, in_addr_t addr, uint16_t p): syscallUUID{uuid}, processid{pid},sourceip{addr}, sourceport{p} {};
  };

  struct ListeningStatus{
    UUID syscallUUID;
    int processid;
    in_addr_t sourceip;
    uint16_t sourceport;
    int queueMaxLen;
    list<StatusKey> handshakingStatusKeyList;
    list<StatusKey> establishedStatusKeyList;
    list<WaitingKey> waitingStatusKeyList;
    ListeningStatus(UUID uuid, int pid, in_addr_t addr, uint16_t p, int len): syscallUUID{uuid}, processid{pid}, sourceip{addr}, sourceport{p}, queueMaxLen{len} {
      handshakingStatusKeyList.clear();
      establishedStatusKeyList.clear();
      waitingStatusKeyList.clear();
    };
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
    SocketFD listeningfd;
    in_addr_t clientaddress;
    uint16_t clientport;
    in_addr_t myaddress;
    uint16_t myport;
    int seqNum;

    SynRcvdStatus(UUID uuid, int pid, int lfd, in_addr_t saddr, uint16_t sp, in_addr_t caddr, uint16_t cp, int seq): syscallUUID{uuid}, processid{pid}, listeningfd{lfd}, clientaddress{caddr}, clientport{cp}, myaddress{saddr}, myport{sp}, seqNum{seq} {};
  };

  struct EstabStatus{
    UUID syscallUUID;
    int processid;
    in_addr_t destinationaddress;
    uint16_t destinationport;
    in_addr_t sourceaddress;
    uint16_t sourceport;
    EstabStatus(UUID uuid, int pid, in_addr_t daddr, uint16_t dp, in_addr_t saddr, uint16_t sp): syscallUUID{uuid}, processid{pid}, destinationaddress{daddr}, destinationport{dp}, sourceaddress{saddr}, sourceport{sp} {};
  };

  using StatusVar = variant<ClosedStatus, BindStatus, ListeningStatus, SysSentStatus, SynRcvdStatus, EstabStatus>;
};

class TCPAssignment : public HostModule,
                      private RoutingInfoInterface,
                      public SystemCallInterface,
                      public TimerModule {
private:
  virtual void timerCallback(std::any payload) final;
  map<socket_data::StatusKey, socket_data::StatusVar> SocketStatusMap;
  list<UUID> SyscallStacks;

public:
  TCPAssignment(Host &host);
  virtual void initialize();
  virtual void finalize();
  virtual ~TCPAssignment();
  enum HandShakePacketType{
    PACKET_TYPE_NOT_DECLARED,
    PACKET_TYPE_SYN,
    PACKET_TYPE_SYNACK,
    PACKET_TYPE_ACK
  };

protected:
  virtual void systemCallback(UUID syscallUUID, int pid,
                              const SystemCallParameter &param) final;
  virtual void packetArrived(std::string fromModule, Packet &&packet) final;
  virtual void catchAccept(int listeningfd, int processid);

private:
  void syscall_socket(UUID syscallUUID, int pid, int domain, int type, int protocol);
  void syscall_close(UUID syscallUUID, int pid, int sockfd);
  void syscall_connect(UUID syscallUUID, int pid, int sockfd, struct sockaddr * addr, socklen_t addrlen);
  void syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog);
  void syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr * addr, socklen_t * addrlen);
  void syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr * addr, socklen_t addrlen);
  void syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr * addr, socklen_t * addrlen);
  void syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr * addr, socklen_t * addrlen);
  void returnSystemCallCustom(UUID syscallUUID, int var);
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
