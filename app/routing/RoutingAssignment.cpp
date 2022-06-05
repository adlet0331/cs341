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
  tabelupdated = true;

  int size = RoutingtableSize();

  MyPacket requestPacket((size_t)(46 + 20*size));
  ipv4_t broadIP;
  broadIP[0] = (uint8_t)255;
  broadIP[1] = (uint8_t)255;
  broadIP[2] = (uint8_t)255;
  broadIP[3] = (uint8_t)255;
  uint32_t dest_IP = NetworkUtil::arrayToUINT64(broadIP);
  
  requestPacket.IPAddrWrite(routerIP,dest_IP,(uint16_t)(32+(20*size)));
  requestPacket.UDPWrite((uint16_t)520,(uint16_t)520, (uint16_t)(12+(20*size)));
  requestPacket.RIPWrite((uint8_t)1, (uint8_t)1, (uint16_t)0,routingtable, routerIP);

  sendPacket("IPv4", std::move(requestPacket.pkt));
  addTimer(NULL, EstimatedRTT);
}

void RoutingAssignment::finalize() {}

/**
 * @brief Query cost for a host
 *
 * @param ipv4 querying host's IP address
 * @return cost or -1 for no found host
 */
Size RoutingAssignment::ripQuery(const ipv4_t &ipv4) {
  uint32_t dest_ip = NetworkUtil::arrayToUINT64(ipv4);
  return (Size)routingtable[make_pair(routerIP,dest_ip)];
}

void RoutingAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  MyPacket arrivedPacket(packet);
  uint64_t source_ip = arrivedPacket.source_ip();
  ipv4_t array_source_ip = NetworkUtil::UINT64ToArray<4>(source_ip);
  uint8_t command = arrivedPacket.command();

  if(command == (uint8_t) 1) {
    // 첫 reqeust일 때
    
    routingtable[make_pair(routerIP,source_ip)] = 1;
    
    int size = RoutingtableSize();
    MyPacket responsePacket((size_t)(46 + 20*size));

    responsePacket.IPAddrWrite(routerIP,source_ip,(uint16_t)(32+(20*size)));
    responsePacket.UDPWrite((uint16_t)520,(uint16_t)520, (uint16_t)(12+(20*size)));
    responsePacket.RIPWrite((uint8_t)2, (uint8_t)1, (uint16_t)2,routingtable, routerIP);

    sendPacket("IPv4", std::move(responsePacket.pkt));

    tabelupdated = true;
  } else {
    //response 일 때
    size_t table_size = (arrivedPacket.pkt.getSize() - (size_t)46)/20;
    for(size_t i = 0; i <table_size;i++) {
      uint32_t dest_ip;
      uint32_t matric;
      arrivedPacket.pkt.readData((size_t)(62 + 20*i), &matric, (size_t)4);
      arrivedPacket.pkt.readData((size_t)(50 + 20*i), &dest_ip, (size_t)4);
      matric = ntohl(matric);
      ipv4_t array_dest_ip = NetworkUtil::UINT64ToArray<4>((uint64_t)dest_ip);
      
      if(routingtable.count(make_pair(source_ip,dest_ip)) ==1) {
        
        if(routingtable[make_pair(source_ip,dest_ip)] > (size_t)matric){
          tabelupdated = true;
          routingtable[make_pair(source_ip,dest_ip)] = (size_t)matric;
          
          if(routingtable[make_pair(routerIP,dest_ip)] >
             routingtable[make_pair(routerIP,source_ip)] + routingtable[make_pair(source_ip,dest_ip)]) {
               routingtable[make_pair(routerIP,dest_ip)] = routingtable[make_pair(routerIP,source_ip)] + routingtable[make_pair(source_ip,dest_ip)];
             }
        }
      }else {
        tabelupdated = true;

        routingtable[make_pair(source_ip,dest_ip)] = (size_t)matric;

        if(routingtable.count(make_pair(routerIP,dest_ip)) ==1 ) {
          if(routingtable[make_pair(routerIP,dest_ip)] >
             routingtable[make_pair(routerIP,source_ip)] + routingtable[make_pair(source_ip,dest_ip)]) {
               routingtable[make_pair(routerIP,dest_ip)] = routingtable[make_pair(routerIP,source_ip)] + routingtable[make_pair(source_ip,dest_ip)];
             }
        }
        else {
          routingtable[make_pair(routerIP,dest_ip)] = routingtable[make_pair(routerIP,source_ip)] + routingtable[make_pair(source_ip,dest_ip)];
        }
      }
    }
  }

  printf("packet get!\n");
}

void RoutingAssignment::timerCallback(std::any payload) {
  // Remove below
  printf("timerring\n");
  if(tabelupdated) {
    tabelupdated = false;

    int size = RoutingtableSize();
    MyPacket responsePacket((size_t)(46 + 20*size));

    ipv4_t broadIP;
    broadIP[0] = (uint8_t)255;
    broadIP[1] = (uint8_t)255;
    broadIP[2] = (uint8_t)255;
    broadIP[3] = (uint8_t)255;
    uint32_t dest_IP = NetworkUtil::arrayToUINT64(broadIP);

    responsePacket.IPAddrWrite(routerIP,dest_IP,(uint16_t)(32+(20*size)));
    responsePacket.UDPWrite((uint16_t)520,(uint16_t)520, (uint16_t)(12+(20*size)));
    responsePacket.RIPWrite((uint8_t)2, (uint8_t)1, (uint16_t)2,routingtable, routerIP);

    sendPacket("IPv4", std::move(responsePacket.pkt));
    addTimer(NULL,EstimatedRTT);
  }
}

void RoutingAssignment::getSelfIP() {
  ipv4_t broadIP;
  broadIP[0] = (uint8_t)255;
  broadIP[1] = (uint8_t)255;
  broadIP[2] = (uint8_t)255;
  broadIP[3] = (uint8_t)255;

  uint16_t NIC_port = getRoutingTable(broadIP);
  array_routerIP = getIPAddr(NIC_port).value();
  routerIP = (uint32_t)NetworkUtil::arrayToUINT64(array_routerIP);
  printf("%d. %d. %d. %d \n",array_routerIP[0],array_routerIP[1],array_routerIP[2],array_routerIP[3]);
}

int RoutingAssignment::RoutingtableSize() {
  int size = 0;
  for(auto iter = routingtable.begin(); iter != routingtable.end(); ++iter) {
    if(iter->first.first == routerIP) size++;
  }
  return size;
}

void MyPacket::IPAddrWrite(uint32_t s_addr, uint32_t d_addr, uint16_t datalen) { 
  pkt.writeData((size_t)26, &s_addr, (size_t)4);
  pkt.writeData((size_t)30, &d_addr, (size_t)4);
  datalen = htons(datalen);
  pkt.writeData((size_t)16, &datalen, (size_t)2);
}

void MyPacket::UDPWrite(uint16_t s_port, uint16_t d_port, uint16_t len) {
  s_port = htons(s_port);
  d_port = htons(d_port);
  len = htons(len);
  pkt.writeData((size_t)34, &s_port, (size_t)2);
  pkt.writeData((size_t)36, &d_port, (size_t)2);
  pkt.writeData((size_t)38, &len, (size_t)2);
}

void MyPacket::RIPWrite(uint8_t command, uint8_t version, uint16_t familyidnetifier, 
                        map<pair<uint32_t, uint32_t>,size_t> routingtable, uint32_t routerIP) {

  pkt.writeData((size_t)42, &command, (size_t)1);
  pkt.writeData((size_t)43, &version, (size_t)1);
  if(command==1) {
    uint32_t matric = (uint32_t)16;
    matric = htonl(matric);
    pkt.writeData((size_t)(62), &matric, (size_t)4);
  } else {
    int nsize = 0;
    familyidnetifier = htons(familyidnetifier);
    for(auto iter = routingtable.begin(); iter != routingtable.end(); ++iter) {
      if(iter->first.first == routerIP) {
        pkt.writeData((size_t)(46 + 20*nsize), &familyidnetifier, (size_t)2);
        uint32_t destip =iter->first.second;
        pkt.writeData((size_t)(50 + 20*nsize), &destip, (size_t)4);
        uint32_t matric = (uint64_t)iter->second;
        matric = htonl(matric);
        pkt.writeData((size_t)(62 + 20*nsize), &matric, (size_t)4);
        nsize++;
      }
    }
  }
}

uint32_t MyPacket::source_ip() {
  uint32_t ret;
  this->pkt.readData((size_t)26,&ret, (size_t)4);
  return ret;
}

uint8_t MyPacket::command() {
  uint8_t ret;
  this->pkt.readData((size_t)42, &ret, (size_t)1);
  return ret;
}


} // namespace E
