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
#include <arpa/inet.h> //지켜봐야 할놈, hton, ntoh등이 안먹어서 쓰긴 했는데 나중을 지켜봐야함

using namespace std;

namespace E {

RoutingAssignment::RoutingAssignment(Host &host)
    : HostModule("UDP", host), RoutingInfoInterface(host),
      TimerModule("UDP", host) {
      }

RoutingAssignment::~RoutingAssignment() {}

void RoutingAssignment::initialize() {
  getSelfIP();

  MyPacket requestPacket((size_t)46);
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
  linkCost(123);
  (void)packet;
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
  ipv4_t routerIP = getIPAddr(NIC_port).value();
  printf("%d. %d. %d. %d \n",routerIP[0],routerIP[1],routerIP[2],routerIP[3]);
}

void MyPacket::IPAddrWrite(uint32_t s_addr, uint32_t d_addr, uint16_t datalen) {
  pkt.writeData((size_t)26, &s_addr, (size_t)4);
  pkt.writeData((size_t)30, &d_addr, (size_t)4);
  datalen = htons(datalen);
  pkt.writeData((size_t)16, &datalen, (size_t)2);
}

void MyPacket::UDPWrite(uint16_t s_port, uint16_t d_port, uint16_t len) {
  pkt.writeData((size_t)34, &d_port, (size_t)2);
  pkt.writeData((size_t)34, &s_port, (size_t)2);
  pkt.writeData((size_t)34, &len, (size_t)2);
}


} // namespace E
