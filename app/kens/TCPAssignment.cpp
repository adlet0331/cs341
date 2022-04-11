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
#include <random>

using namespace std;

namespace E {

// New Data Structure

// key : file descripter

TCPAssignment::TCPAssignment(Host &host)
    : HostModule("TCP", host), RoutingInfoInterface(host),
      SystemCallInterface(AF_INET, IPPROTO_TCP, host),
      TimerModule("TCP", host) {}

TCPAssignment::~TCPAssignment() {}

void TCPAssignment::initialize() {
  for(auto iter = SyscallStacks.begin(); iter!= SyscallStacks.end();iter++)
  {
    this->returnSystemCall(*iter, 0);
  }
}

void TCPAssignment::finalize() {}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid,
                                   const SystemCallParameter &param) {
  SyscallStacks.push_back(syscallUUID);

  switch (param.syscallNumber) {
    case SOCKET:
      //2번째 인자 추가함
      this->syscall_socket(syscallUUID, pid, get<int>(param.params[0]),
              get<int>(param.params[1]), get<int>(param.params[2]));
      break;
    case CLOSE:
      this->syscall_close(syscallUUID, pid, get<int>(param.params[0]));
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
      this->syscall_bind(
          syscallUUID, pid, get<int>(param.params[0]),
          static_cast<struct sockaddr *>(get<void *>(param.params[1])),
          (socklen_t)get<int>(param.params[2]));
      break;
    }
    case GETSOCKNAME:{
      this->syscall_getsockname(
          syscallUUID, pid, get<int>(param.params[0]),
          static_cast<struct sockaddr *>(get<void *>(param.params[1])),
          static_cast<socklen_t *>(get<void *>(param.params[2])));
      break;
    }
    case GETPEERNAME:{
      this->syscall_getpeername(
          syscallUUID, pid, get<int>(param.params[0]),
          static_cast<struct sockaddr *>(get<void *>(param.params[1])),
          static_cast<socklen_t *>(get<void *>(param.params[2])));
      break;
  }
    default:{
      assert(0);
    }
  }
  return;
}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int type, int protocol){
  if (domain != AF_INET) printf("SYSCALL_SOCKET: domain != AF_INET\n");
  if (type != SOCK_STREAM) printf("SYSCALL_SOCKET: type != SOCK_STREAM\n");
  if (protocol != IPPROTO_TCP) printf("SYSCALL_SOCKET: protocol != IPPROTO_TCP\n");

  int socketfd = createFileDescriptor(pid);

  SocketStatusMap[make_pair(socketfd, pid)] = socket_data::ClosedStatus{syscallUUID, pid}; 

  this->returnSystemCallCustom(syscallUUID, socketfd);
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int sockfd){
  removeFileDescriptor(pid, sockfd);
  
  if (pid >= 0 && sockfd >= 0){
    struct socket_data::EstabStatus* thisListeningsocketPointer = get_if<socket_data::EstabStatus>(&SocketStatusMap.find({sockfd, pid})->second);
    SocketStatusMap.erase(make_pair(sockfd, pid));
    

    // for(auto iter = thisListeningsocketPointer->handshakingStatusKeyList.begin(); iter != thisListeningsocketPointer->handshakingStatusKeyList.end(); iter++) {
    //   if (iter->first == sockfd && iter->second == pid){
    //     thisListeningsocketPointer->handshakingStatusKeyList.remove({sockfd, pid});
    //     break;
    //   }
    // }
    // for(auto iter2 = thisListeningsocketPointer->establishedStatusKeyList.begin(); iter2 != thisListeningsocketPointer->establishedStatusKeyList.end(); iter2++) {
    //   if (iter2->first == sockfd && iter2->second == pid){
    //     thisListeningsocketPointer->establishedStatusKeyList.remove({sockfd, pid});
    //     break;
    //   }
    // }

    this->returnSystemCallCustom(syscallUUID, 0);
  }

  this->returnSystemCallCustom(syscallUUID, -1);
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int sockfd, struct sockaddr * addr, socklen_t addrlen){
  // 이미 할당된 sockfd가 없음
  struct socket_data::ClosedStatus* currClosedSocket = get_if<socket_data::ClosedStatus>(&SocketStatusMap.find(make_pair(sockfd, pid))->second);
  struct socket_data::BindStatus* currBindSocket = get_if<socket_data::BindStatus>(&SocketStatusMap.find(make_pair(sockfd, pid))->second);
  if (currClosedSocket == nullptr && currBindSocket == nullptr) this->returnSystemCallCustom(syscallUUID, -1);

  in_addr_t server_ip = ((sockaddr_in *)addr)->sin_addr.s_addr;
  uint16_t server_port = ntohs(((sockaddr_in *)addr)->sin_port);

  // 클라 IP 받기
  ipv4_t server_address_array = NetworkUtil::UINT64ToArray<4> (server_ip);
  uint16_t NIC_port = getRoutingTable(server_address_array);
  std::optional<ipv4_t> client_address_array = getIPAddr(NIC_port);
  in_addr_t client_ip = NetworkUtil::arrayToUINT64(client_address_array.value());

  // 랜덤하고 안 겹치는 포트 할당
  int client_port;

  random_device portrd;
  mt19937 portgen(portrd());
  uniform_int_distribution<int> portdis(0, 20000);

  int isAlreadyBinded = false;
  struct socket_data::BindStatus* currBindStatus = get_if<socket_data::BindStatus>(&SocketStatusMap.find(make_pair(sockfd, pid))->second);
  if (currBindStatus != nullptr){
    isAlreadyBinded = true;
    client_port = currBindStatus->port;
  }
  
  while(!isAlreadyBinded)
  {
    client_port = portdis(portgen);
    isAlreadyBinded = true;
    for(auto iter = SocketStatusMap.begin(); iter != SocketStatusMap.end(); iter++) {
      socket_data::StatusKey statuskey = iter->first;
      socket_data::StatusVar& currsock = iter->second;
      struct socket_data::BindStatus* currbindedsock = get_if<socket_data::BindStatus>(&currsock);
      if (currbindedsock == nullptr) continue;
      if(currbindedsock->processid != pid) continue;

      if(currbindedsock->address == INADDR_ANY && currbindedsock->port == client_port){
        isAlreadyBinded = false;
        break;
      }

      if(currbindedsock->address == client_ip && currbindedsock->port == client_port){
        isAlreadyBinded = false;
        break;
      }
    }
  }
  printf("PRINT RANDOM PORT: %d\n", client_port);

  //랜덤한 SeqNum 결정
  random_device rd;
  mt19937 gen(rd());
  uniform_int_distribution<int> dis(0, 1000000000);
  int randSeqNum = dis(gen);

  MyPacket fstPacket((size_t)54);

  fstPacket.IPAddrWrite(client_ip,server_ip);
  fstPacket.TCPHeadWrite(client_ip, server_ip, client_port, server_port, randSeqNum, 0, 0b10);

  // Status Change Listen -> SysSent 
  SocketStatusMap[make_pair(sockfd, pid)] = socket_data::SysSentStatus(syscallUUID, pid, server_ip, server_port, client_ip, client_port);

  //패킷 Send
  this->sendPacket("IPv4", std::move(fstPacket.pkt));
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog){
  struct socket_data::BindStatus* currBindedSocket = get_if<socket_data::BindStatus>(&SocketStatusMap.find(make_pair(sockfd, pid))->second);
  if (currBindedSocket == nullptr) this->returnSystemCallCustom(syscallUUID, -1);

  SocketStatusMap[make_pair(sockfd, pid)] = socket_data::ListeningStatus{syscallUUID, pid, currBindedSocket->address, currBindedSocket->port, backlog};

  this->returnSystemCallCustom(syscallUUID, 0);
  return;
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr * addr, socklen_t * addrlen){
  struct socket_data::ListeningStatus* currListeningStatus = get_if<socket_data::ListeningStatus>(&SocketStatusMap.find(make_pair(sockfd, pid))->second);
  in_addr_t listening_ip = currListeningStatus->address;
  uint16_t listening_port = currListeningStatus->port;

  currListeningStatus->waitingStatusKeyList.push_back(make_pair(syscallUUID, addr));

  this->catchAccept(sockfd, pid);
  return;
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr * addr, socklen_t addrlen){
  in_addr_t s_addr = ((sockaddr_in *)addr)->sin_addr.s_addr;
  uint16_t port = ntohs(((sockaddr_in *)addr)->sin_port);

  // sockfd에 bind 된 socket이 있을 때
  if (SocketStatusMap.find(make_pair(sockfd, pid)) != SocketStatusMap.end()){
    // Closed 된 소켓 (Open 되어 있는) 있는지 확인 - 있어야 함
    struct socket_data::ClosedStatus* currClosedSocket = get_if<socket_data::ClosedStatus>(&SocketStatusMap.find(make_pair(sockfd, pid))->second);
    if (currClosedSocket == nullptr){
      this->returnSystemCallCustom(syscallUUID, -1);
      return;
    }

    // sockfd에 이미 bind 된 애가 있을 때 있는지 확인 - 있으면 안되
    struct socket_data::BindStatus* currBindSocket = get_if<socket_data::BindStatus>(&SocketStatusMap.find(make_pair(sockfd, pid))->second);
    if (currBindSocket != nullptr){
      this->returnSystemCallCustom(syscallUUID, -1);
      return;
    }

    // Binded 된 소켓 중 port 가 중복된 것이 있는지 확인
    for(auto iter = SocketStatusMap.begin(); iter != SocketStatusMap.end(); iter++){
      socket_data::StatusKey statuskey = iter->first;
      socket_data::StatusVar& currsock = iter->second;
      struct socket_data::BindStatus* currbindedsock = get_if<socket_data::BindStatus>(&currsock);
      if (currbindedsock != nullptr){
        if(currbindedsock->processid != pid) continue;

        if(currbindedsock->address == INADDR_ANY && currbindedsock->port == port){
          this->returnSystemCallCustom(syscallUUID, -1);
          return;
        }
        if(currbindedsock->address == s_addr && currbindedsock->port == port){
          this->returnSystemCallCustom(syscallUUID, -1);
          return;
        }
      }
    }

    SocketStatusMap[make_pair(sockfd, pid)] = socket_data::BindStatus{syscallUUID, pid, s_addr, port};

    this->returnSystemCallCustom(syscallUUID, 0);
    return;
  }
  else{
    this->returnSystemCallCustom(syscallUUID, -1);
    return;
  }
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr * addr, socklen_t * addrlen){ 
  // TODO : addrlen 에 맞춰 짜르기 구현
  struct socket_data::BindStatus* currBindSocket = get_if<socket_data::BindStatus>(&SocketStatusMap.find({sockfd, pid})->second);
  if (currBindSocket != nullptr){
    ((sockaddr_in *)addr)->sin_addr.s_addr = currBindSocket->address;
    ((sockaddr_in *)addr)->sin_port = htons(currBindSocket->port);
    ((sockaddr_in *)addr)->sin_family = AF_INET;

    this->returnSystemCallCustom(syscallUUID, 0);
    return;
  }

  struct socket_data::ListeningStatus* currListeningSocket = get_if<socket_data::ListeningStatus>(&SocketStatusMap.find({sockfd, pid})->second);
  if (currListeningSocket != nullptr){
    ((sockaddr_in *)addr)->sin_addr.s_addr = currListeningSocket->address;
    ((sockaddr_in *)addr)->sin_port = htons(currListeningSocket->port);
    ((sockaddr_in *)addr)->sin_family = AF_INET;

    this->returnSystemCallCustom(syscallUUID, 0);
    return;
  }
  struct socket_data::SynRcvdStatus* currSynRcvdSocket = get_if<socket_data::SynRcvdStatus>(&SocketStatusMap.find({sockfd, pid})->second);
  if (currSynRcvdSocket != nullptr){
    ((sockaddr_in *)addr)->sin_addr.s_addr = currSynRcvdSocket->myaddress;
    ((sockaddr_in *)addr)->sin_port = htons(currSynRcvdSocket->myport);
    ((sockaddr_in *)addr)->sin_family = AF_INET;
    this->returnSystemCallCustom(syscallUUID, 0);
    return;
  }
  
  struct socket_data::SysSentStatus* currSysSentSocket = get_if<socket_data::SysSentStatus>(&SocketStatusMap.find({sockfd, pid})->second);
  if (currSysSentSocket != nullptr){
    ((sockaddr_in *)addr)->sin_addr.s_addr = currSysSentSocket->myaddress;
    ((sockaddr_in *)addr)->sin_port = htons(currSysSentSocket->myport);
    ((sockaddr_in *)addr)->sin_family = AF_INET;
    this->returnSystemCallCustom(syscallUUID, 0);
    return;
  }

  struct socket_data::EstabStatus* currEstabSocket = get_if<socket_data::EstabStatus>(&SocketStatusMap.find({sockfd, pid})->second);
  if (currEstabSocket != nullptr){
    ((sockaddr_in *)addr)->sin_addr.s_addr = currEstabSocket->sourceaddress;
    ((sockaddr_in *)addr)->sin_port = htons(currEstabSocket->sourceport);
    ((sockaddr_in *)addr)->sin_family = AF_INET;

    this->returnSystemCallCustom(syscallUUID, 0);
    return;
  }

  this->returnSystemCallCustom(syscallUUID, -1);
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr * addr, socklen_t * addrlen){
  struct socket_data::SynRcvdStatus* currSynRcvdSocket = get_if<socket_data::SynRcvdStatus>(&SocketStatusMap.find({sockfd, pid})->second);
  if (currSynRcvdSocket != nullptr){
    ((sockaddr_in *)addr)->sin_addr.s_addr = currSynRcvdSocket->clientaddress;
    ((sockaddr_in *)addr)->sin_port = htons(currSynRcvdSocket->clientport);
    ((sockaddr_in *)addr)->sin_family = AF_INET;
    this->returnSystemCallCustom(syscallUUID, 0);
    return;
  }
  
  struct socket_data::SysSentStatus* currSysSentSocket = get_if<socket_data::SysSentStatus>(&SocketStatusMap.find({sockfd, pid})->second);
  if (currSysSentSocket != nullptr){
    ((sockaddr_in *)addr)->sin_addr.s_addr = currSysSentSocket->serveraddress;
    ((sockaddr_in *)addr)->sin_port = htons(currSysSentSocket->serverport);
    ((sockaddr_in *)addr)->sin_family = AF_INET;
    this->returnSystemCallCustom(syscallUUID, 0);
    return;
  }
  
  struct socket_data::EstabStatus* currEstabSocket = get_if<socket_data::EstabStatus>(&SocketStatusMap.find({sockfd, pid})->second);
  if (currEstabSocket != nullptr){
    ((sockaddr_in *)addr)->sin_addr.s_addr = currEstabSocket->destinationaddress;
    ((sockaddr_in *)addr)->sin_port = htons(currEstabSocket->destinationport);
    ((sockaddr_in *)addr)->sin_family = AF_INET;
    this->returnSystemCallCustom(syscallUUID, 0);
    return;
  }

  this->returnSystemCallCustom(syscallUUID, -1);
  return;
}

void TCPAssignment::catchAccept(int listeningfd, int processid){
// 이 소켓의 Listening Socket FD 가져오기. 없을리 없다
  struct socket_data::ListeningStatus* thisListeningsocket = get_if<socket_data::ListeningStatus>(&SocketStatusMap.find({listeningfd, processid})->second);

  // listening socket의 list들 확인
  while(!thisListeningsocket->establishedStatusKeyList.empty() && !thisListeningsocket->waitingStatusKeyList.empty()){
    socket_data::SocketFD estabedsocket = thisListeningsocket->establishedStatusKeyList.front().first;
    socket_data::ProcessID estabedpid = thisListeningsocket->establishedStatusKeyList.front().second;
    UUID waitingKey = thisListeningsocket->waitingStatusKeyList.front().first;
    struct sockaddr * waitPointer = thisListeningsocket->waitingStatusKeyList.front().second;

    struct socket_data::EstabStatus* thisEstabsocket = get_if<socket_data::EstabStatus>(&SocketStatusMap.find({estabedsocket, estabedpid})->second);

    if (thisEstabsocket == nullptr) return;

    ((sockaddr_in *)waitPointer)->sin_addr.s_addr = thisEstabsocket->sourceaddress;
    ((sockaddr_in *)waitPointer)->sin_family = AF_INET;
    ((sockaddr_in *)waitPointer)->sin_port = htons(thisEstabsocket->sourceport);

    thisListeningsocket->establishedStatusKeyList.pop_front();
    thisListeningsocket->waitingStatusKeyList.pop_front();

    this->returnSystemCallCustom(waitingKey, estabedsocket);
  }
  return;
}

void TCPAssignment::packetArrived(string fromModule, Packet &&packet) {
  // 온 Packet 정보 받아오기
  MyPacket receivedpacket(packet);
  in_addr_t destination_ip = receivedpacket.dest_ip();
  uint16_t destination_port = receivedpacket.dest_port();
  in_addr_t source_ip = receivedpacket.source_ip();
  uint16_t source_port = receivedpacket.source_port();

  // 받은 패킷의 상태 확인 -> 3-way handshake 중 몇 번째 패킷인지 SYNbit 와 ACKbit로 판별
  uint16_t myPacketFlag = receivedpacket.flag() & 0b010010;
  int currPacketType = PACKET_TYPE_NOT_DECLARED;
  if      (myPacketFlag == 0b000010) currPacketType = PACKET_TYPE_SYN;
  else if (myPacketFlag == 0b010010) currPacketType = PACKET_TYPE_SYNACK;
  else if (myPacketFlag == 0b010000) currPacketType = PACKET_TYPE_ACK;

  bool isfinded = false;
  for(auto iter = SocketStatusMap.begin(); iter != SocketStatusMap.end(); iter++){
    socket_data::SocketFD socketfd = get<0>(iter->first);
    socket_data::ProcessID processid = get<1>(iter->first);

    visit(
      overloaded{
        [&](socket_data::ListeningStatus currListeningsock) {
          // Client -> Server. 1번째.  Server 입장
          if (currPacketType != PACKET_TYPE_SYN) return;

          // 순회하면서 SocketStatusMap Pointer 가져오기
          socket_data::ListeningStatus* currListeningsockPointer;
          for(auto iter = SocketStatusMap.begin(); iter != SocketStatusMap.end(); iter++){
            currListeningsockPointer = get_if<socket_data::ListeningStatus>(&iter->second);
            if(currListeningsockPointer->address == currListeningsock.address && currListeningsockPointer->port == currListeningsock.port){
              break;
            }
          }

          // Client가 연결하고자 하는 ListeningSocket 맞을 때
          if((currListeningsockPointer->address == INADDR_ANY && currListeningsockPointer->port == destination_port) || 
          (currListeningsockPointer->address == destination_ip && currListeningsockPointer->port == destination_port)){
            // 사이즈가 같으면 패킷 드롭
            if (currListeningsockPointer->queueMaxLen <= currListeningsockPointer->handshakingStatusKeyList.size()) return;
            // 지금 handshaking 중인 Queue에 넣어주기
            currListeningsockPointer->handshakingStatusKeyList.push_back(make_pair(socketfd, processid));

            UUID uuid = currListeningsockPointer->syscallUUID;
            int processid = currListeningsockPointer->processid;

            // 패킷 보내기
            // SYNbit = 1, Seq = 랜덤, ACKbit = 1, ACKnum = 이전Seq + 1
            MyPacket newpacket{size_t(54)};

            random_device rd;
            mt19937 gen(rd());
            uniform_int_distribution<int> dis(0, 100000000);
            int randSeqNum = dis(gen);

            uint32_t ACKNum = receivedpacket.SeqNum() + 1;
            
            newpacket.IPAddrWrite(destination_ip, source_ip);
            newpacket.TCPHeadWrite(source_ip, destination_ip, destination_port, source_port, randSeqNum, ACKNum, 0b010010);

            sendPacket("IPv4", std::move(newpacket.pkt));

            //SynRcvd 상태인 socket_data 생성해서 넣어주기
            int newsockfd = createFileDescriptor(processid);
            SocketStatusMap[make_pair(newsockfd, processid)] = socket_data::SynRcvdStatus{uuid, processid, socketfd, destination_ip, destination_port, source_ip, source_port, randSeqNum};
          }
        },
        [&](socket_data::SysSentStatus currSysSentsock) {
          // Server -> Client. 2번째
          // SYNbit, Seq 넘버 확인.
          if (currPacketType != PACKET_TYPE_SYNACK) return;
          
          // Server가 연결하고자 하는 SysSentsocket 맞을 때
          if((currSysSentsock.myaddress == INADDR_ANY && currSysSentsock.myport == destination_port) || (currSysSentsock.myaddress == destination_ip && currSysSentsock.myport == destination_port)){
            // TODO : 받은 ACKnum과 이전 SeqNum과 비교. 다르면 거부

            UUID uuid = currSysSentsock.syscallUUID;
            int processid = currSysSentsock.processid;
            
            // 패킷 보내기
            // ACKbit = 1, ACKnum = 이전 Seqnum + 1

            MyPacket newpacket{size_t(54)};

            uint32_t newACKNum = receivedpacket.SeqNum() + 1;
            
            newpacket.IPAddrWrite(destination_ip, source_ip);
            newpacket.TCPHeadWrite(destination_ip, source_ip, destination_port, source_port, 0, newACKNum, 0b010000);

            //EstabStatus 상태인 socket_data 생성해서 넣어주기
            SocketStatusMap[make_pair(socketfd, processid)] = socket_data::EstabStatus{uuid, processid, source_ip, source_port, destination_ip, destination_port};

            this->sendPacket("IPv4", std::move(newpacket.pkt));

            // Server에 Send Packet 까지 완료 Connect System Call 리턴해주기
            this->returnSystemCallCustom(uuid, 0);
            return;
          }
          // Make New Socket Data Status: ESTAB
        },
        [&](socket_data::SynRcvdStatus currSynRcvdsock) {
          // Client -> Server. 3번째
          // ACKbit, ACKnum 확인. ESTAB
          if (currPacketType != PACKET_TYPE_ACK) return;
          
          // Client가 연결하고자 하는 SysSentsocket가 맞을 때
          if((currSynRcvdsock.myaddress == INADDR_ANY && currSynRcvdsock.myport == destination_port) || 
          (currSynRcvdsock.myaddress == destination_ip && currSynRcvdsock.myport == destination_port)){
            // TODO : 받은 ACKnum과 이전 SeqNum과 비교. 다르면 거부

            UUID uuid = currSynRcvdsock.syscallUUID;
            int processid = currSynRcvdsock.processid;
            int listeningfd = currSynRcvdsock.listeningfd;

            // 이 소켓이 첫번째 소켓을 받은 직후 생긴 Listening Socket FD 가져오기 
            struct socket_data::ListeningStatus* thisListeningsocketPointer = get_if<socket_data::ListeningStatus>(&SocketStatusMap.find({listeningfd, processid})->second);
            thisListeningsocketPointer->handshakingStatusKeyList.remove({listeningfd, processid});

            //Estab 상태인 socket_data 생성해서 넣어주기
            SocketStatusMap[make_pair(socketfd, processid)] = socket_data::EstabStatus{uuid, processid, source_ip, source_port, destination_ip, destination_port};
            thisListeningsocketPointer->establishedStatusKeyList.push_back(make_pair(socketfd, processid));
            
            this->catchAccept(listeningfd, processid);
          }
        },
        [](auto sock_data) {
          // 위의 상태와 다른 경우. 에러처리
          return;

        },
      }, iter->second);
      if (isfinded) return;
  }
}

void TCPAssignment::timerCallback(any payload) {}

void TCPAssignment::returnSystemCallCustom(UUID systemCall, int val) {
  
  for(auto iter = SyscallStacks.begin(); iter!= SyscallStacks.end();iter++)
  {
    if(systemCall == *iter){
      SyscallStacks.erase(iter);
      break;
    }
  }
  this->returnSystemCall(systemCall, val);
}

void MyPacket::IPAddrWrite(in_addr_t s_addr, in_addr_t d_addr) {
  pkt.writeData((size_t)26, &s_addr, (size_t)4);
  pkt.writeData((size_t)30, &d_addr, (size_t)4);
}

void MyPacket::TCPHeadWrite(in_addr_t source_ip, in_addr_t dest_ip, 
    uint16_t source_port, uint16_t dest_port, uint32_t SeqNum, uint32_t ACKNum, uint16_t flag) {
  source_port = htons(source_port);
  this->pkt.writeData((size_t)34, &source_port, (size_t)2);
  dest_port = htons(dest_port);
  this->pkt.writeData((size_t)36, &dest_port, (size_t)2);
  SeqNum = htonl(SeqNum);
  this->pkt.writeData((size_t)38, &SeqNum, (size_t)4);
  ACKNum = htonl(ACKNum);
  this->pkt.writeData((size_t)42, &ACKNum, (size_t)4);

  flag = htons((0b0101000000000000) + (flag));
  this->pkt.writeData((size_t)46, &flag, (size_t)2);
  uint16_t window =51200;
  window = htons(window);
  this->pkt.writeData((size_t)48, &window, (size_t)2);
  uint8_t buffer[20]={0,};
  uint16_t zero =0;
  this->pkt.writeData((size_t)50, &zero, (size_t)2);
  this->pkt.readData(34,buffer,20);

  uint16_t checkSum = 65535 - NetworkUtil::tcp_sum(source_ip,dest_ip,buffer,(size_t)20);
  checkSum = htons(checkSum);
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
  ret = ntohs(ret);
  return ret;
}

uint16_t MyPacket::dest_port() {
  uint16_t ret;
  this->pkt.readData((size_t)36, &ret, (size_t)2);
  ret = ntohs(ret);
  return ret;
}

uint32_t MyPacket::SeqNum() {
  uint32_t ret;
  this->pkt.readData((size_t)38, &ret, (size_t)4);
  ret = (ntohl(ret));
  return ret;
}

uint32_t MyPacket::ACKNum() {
  uint32_t ret;
  this->pkt.readData((size_t)42, &ret, (size_t)4);
  ret = (ntohl(ret));
  return ret;
}

uint16_t MyPacket::flag() {
  uint16_t ret;
  this->pkt.readData((size_t)46, &ret, (size_t)2);
  ret = (ntohs(ret) &0b111111);
  return ret;
}

void MyPacket::ACKNumAdd(int n) {
  uint32_t ACKNum = this->ACKNum();
  ACKNum += n;
  ACKNum = htonl(ACKNum);
  this->pkt.writeData((size_t)42, &ACKNum, (size_t)4);
}

void MyPacket::SeqNumAdd(int n) {
  uint32_t SeqNum = this->SeqNum();
  SeqNum += n;
  SeqNum = htonl(SeqNum);
  this->pkt.writeData((size_t)38, &SeqNum, (size_t)4);
}

} // namespace E

