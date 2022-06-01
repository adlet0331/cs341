/*
 * E_RoutingAssignment.cpp
 *
 */

#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Packet.hpp>
#include <cerrno>
#include <list>
#include <functional>
#include <iostream>
#include "RoutingAssignment.hpp"
#include <netinet/in.h>

using namespace std;

namespace E {

RoutingAssignment::RoutingAssignment(Host &host)
    : HostModule("UDP", host), RoutingInfoInterface(host),
      TimerModule("UDP", host) {
      }

RoutingAssignment::~RoutingAssignment() {}

void RoutingAssignment::initialize() {
  
  getSelfIP();
  
  routingtable[make_pair(routerIP,routerIP)] = (size_t)0;

  int size = RoutingtableSize();

  MyPacket requestPacket((size_t)(46 + 20*size));
  uint32_t source_IP = NetworkUtil::arrayToUINT64(routerIP);
  ipv4_t broadIP;
  broadIP[0] = (uint8_t)255;
  broadIP[1] = (uint8_t)255;
  broadIP[2] = (uint8_t)255;
  broadIP[3] = (uint8_t)255;
  uint32_t dest_IP = NetworkUtil::arrayToUINT64(broadIP);
  
  requestPacket.IPAddrWrite(source_IP,dest_IP,(uint16_t)(28+(20*size)));
  requestPacket.UDPWrite((uint16_t)520,(uint16_t)520, (uint16_t)(8+(20*size)));
  requestPacket.RIPWrite((uint8_t)1, (uint8_t)1, (uint16_t)0,routingtable, routerIP);

  sendPacket("IPv4", std::move(requestPacket.pkt));

  printf("hello world!\n");
}

void RoutingAssignment::finalize() {}

/**
 * @brief Query cost for a host
 *
 * @param ipv4 querying host's IP address
 * @return cost or -1 for no found host
 */
Size RoutingAssignment::ripQuery(const ipv4_t &ipv4) {
  // Implement below

  return -1;
}

void RoutingAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  // Remove below
  (void)fromModule;
  (void)packet;
  printf("packet get!\n");
}

void RoutingAssignment::timerCallback(std::any payload) {
  // Remove below
  (void)payload;
}

void RoutingAssignment::getSelfIP() {
  ipv4_t broadIP;
  broadIP[0] = (uint8_t)255;
  broadIP[1] = (uint8_t)255;
  broadIP[2] = (uint8_t)255;
  broadIP[3] = (uint8_t)255;

  uint16_t NIC_port = getRoutingTable(broadIP);
  routerIP = getIPAddr(NIC_port).value();
  printf("%d. %d. %d. %d \n",routerIP[0],routerIP[1],routerIP[2],routerIP[3]);
}

void MyPacket::IPAddrWrite(uint32_t s_addr, uint32_t d_addr, uint16_t datalen) { 
  pkt.writeData((size_t)26, &s_addr, (size_t)4);
  pkt.writeData((size_t)30, &d_addr, (size_t)4);
  datalen = htons(datalen);
  pkt.writeData((size_t)16, &datalen, (size_t)2);
}

void MyPacket::UDPWrite(uint16_t s_port, uint16_t d_port, uint16_t len) {
  pkt.writeData((size_t)34, &s_port, (size_t)2);
  pkt.writeData((size_t)36, &d_port, (size_t)2);
  pkt.writeData((size_t)38, &len, (size_t)2);
}

int RoutingAssignment::RoutingtableSize() {
  int size = 0;
  for(auto iter = routingtable.begin(); iter != routingtable.end(); ++iter) {
    if(iter->first.first[3] == routerIP[3])
      size++;
  }
  return size;
}

void MyPacket::RIPWrite(uint8_t command, uint8_t version, uint16_t familyidnetifier, 
                        map<pair<ipv4_t, ipv4_t>,size_t> routingtable, ipv4_t routerIP) {
  pkt.writeData((size_t)42, &command, (size_t)1);
  pkt.writeData((size_t)43, &version, (size_t)1);
  int nsize = 0;
  for(auto iter = routingtable.begin(); iter != routingtable.end(); ++iter) {
    if(iter->first.first[3] == routerIP[3])
      pkt.writeData((size_t)(46 + 20*nsize), &familyidnetifier, (size_t)2);
      uint32_t IP = NetworkUtil::arrayToUINT64(iter->first.second);
      pkt.writeData((size_t)(50 + 20*nsize), &IP, (size_t)4);
      uint32_t matric = (uint64_t)iter->second;
      pkt.writeData((size_t)(62 + 20*nsize), &matric, (size_t)4);
      nsize++;
  }
}


} // namespace E
