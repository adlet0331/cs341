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
  bool isSent;
  UUID syscallUUID;
  MyPacket(size_t in_size): pkt{Packet(in_size)}, isSent{false} {}
  MyPacket(Packet packet): pkt{packet}, isSent{false}  {}
  void IPAddrWrite(in_addr_t s_addr, in_addr_t d_addr, uint16_t datalen);
  void TCPHeadWrite(in_addr_t source_ip, in_addr_t dest_ip, uint16_t source_port, uint16_t dest_port, uint32_t SeqNum, uint32_t AckNum, uint16_t flag, void * data_addr, size_t data_size); 
  in_addr_t source_ip();
  in_addr_t dest_ip();
  uint16_t source_port();
  uint16_t dest_port();
  uint32_t SeqNum();
  uint32_t ACKNum();
  uint16_t flag(); 
  bool checksum();
  uint16_t getdatasize();
  uint16_t makechecksum(uint32_t source_ip, uint32_t dest_ip, size_t length);

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
  
  using BufferQueue = list<MyPacket>;
  using BufferQueueMap = map<socket_data::StatusKey, BufferQueue>;
  struct BufferData{
    bool isWriter;
    SocketFD sockfd;
    ProcessID pid;
    uint32_t ACK;
    uint32_t SEQ;
    Time startTime;
    BufferData(bool is, int fd, int pid, uint32_t ack, uint32_t seq, Time time): isWriter{is}, sockfd{fd}, pid{pid}, ACK{ack}, SEQ{seq}, startTime{time} {};
  };
  using BufferDataMap = map<socket_data::StatusKey, BufferData>;

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
    in_addr_t serverip;
    uint16_t serverport;
    in_addr_t myip;
    uint16_t myport;
    SysSentStatus(UUID uuid, int pid, in_addr_t saddr, uint16_t sp, in_addr_t caddr, uint16_t cp): syscallUUID{uuid}, processid{pid}, serverip{saddr}, serverport{sp}, myip{caddr}, myport{cp} {};
  };

  struct SynRcvdStatus{
    UUID syscallUUID;
    int processid;
    SocketFD listeningfd;
    in_addr_t clientip;
    uint16_t clientport;
    in_addr_t myip;
    uint16_t myport;
    uint32_t seqNum;

    SynRcvdStatus(UUID uuid, int pid, int lfd, in_addr_t saddr, uint16_t sp, in_addr_t caddr, uint16_t cp, uint32_t seq): syscallUUID{uuid}, processid{pid}, listeningfd{lfd}, clientip{caddr}, clientport{cp}, myip{saddr}, myport{sp}, seqNum{seq} {};
  };

  struct EstabStatus{
    UUID syscallUUID;
    int processid;
    in_addr_t destinationip;
    uint16_t destinationport;
    in_addr_t sourceip;
    uint16_t sourceport;
    uint32_t SEQ;
    uint64_t ACK;
    EstabStatus(UUID uuid, int pid, in_addr_t daddr, uint16_t dp, in_addr_t saddr, uint16_t sp, uint32_t seq, uint32_t ack): syscallUUID{uuid}, processid{pid}, destinationip{daddr}, destinationport{dp}, sourceip{saddr}, sourceport{sp}, SEQ{seq}, ACK{ack} {};
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
  map<socket_data::StatusKey, pair<void*, size_t>> SocketReceiveBufferMap;
  socket_data::BufferQueueMap SocketSendBufferMap;
  map<socket_data::StatusKey, tuple<UUID,void*,size_t>> SocketReadMap;
  socket_data::BufferQueueMap SocketPacketAwaitingMap;

  int SenderBufferSize = 10;
  list<pair<UUID, SystemCallParameter>> SyscallStacks;

  Time EstimatedRTT = (uint64_t) 1e7;
  Time DevRTT = (uint64_t) 0;

public:
  TCPAssignment(Host &host);
  virtual void initialize();
  virtual void finalize();
  virtual ~TCPAssignment();
  enum HandShakePacketType{
    PACKET_TYPE_NOT_DECLARED,
    PACKET_TYPE_SYN,
    PACKET_TYPE_SYNACK,
    PACKET_TYPE_ACK,
    PACKET_TYPE_FINISH
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
  void syscall_read(UUID syscallUUID, int pid, int sockfd, void * addr, size_t addrlen);
  void push_and_trigger(int pid, int sockfd, MyPacket packet);
  void trigger_sendqueue(int sockfd, int pid);
  void trigger_read(int sockfd, int pid);
  void syscall_write(UUID syscallUUID, int pid, int sockfd, void * addr, size_t addrlen);
  void returnSystemCallCustom(UUID syscallUUID, int var);
  void send_unreliable_packet(int sockfd, int pid, MyPacket myPacket);
  void received_unreliable_packet(int sockfd, int pid, MyPacket MyPacket);
  void UpdateTOI(Time sendTime);
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
