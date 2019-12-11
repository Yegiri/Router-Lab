#include "rip.h"
#include "router.h"
#include "router_hal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern void update(bool insert, RoutingTableEntry entry);
extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index);
extern bool forward(uint8_t *packet, size_t len);
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer);
extern void Show();

extern RoutingTableEntry table[150];
extern int Next[150];
extern int cnt;


uint8_t packet[2048];
uint8_t output[2048];
// 0: 10.0.0.1
// 1: 10.0.1.1
// 2: 10.0.2.1
// 3: 10.0.3.1
// 你可以按需进行修改，注意端序
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0203a8c0, 0x0104a8c0, 0x0102000a,
                                     0x0103000a};
// multicast MAC for 224.0.0.9 is 01:00:5e:00:00:09
in_addr_t multicastIP = 0x090000e0;
macaddr_t multicastMac = {0x01, 0x00, 0x5e, 0x00, 0x00, 0x09};


void create_header(uint32_t totalLen, int i, int num){
    //V=4 & IHL=5
    output[0] = 0x45;
    //TOS=0
    output[1] = 0;
    //Total Length
    output[2] = totalLen >> 8;
    output[3] = totalLen & 0xff;
    //id=0
    output[4] = 0;
    output[5] = 0;
    //Flags=0 & OFF = 0
    output[6] = 0;
    output[7] = 0;
    //TTL=1
    output[8] = 1;
    //Protocol UDP17
    output[9] = 0x11;
    //source address
    output[12] = addrs[i] & 0xff;
    output[13] = (addrs[i] >> 8) & 0xff;
    output[14] = (addrs[i] >> 16) & 0xff;
    output[15] = (addrs[i] >> 24) & 0xff;
    //destination address
    output[16] = multicastIP & 0xff;
    output[17] = (multicastIP >> 8) & 0xff;
    output[18] = (multicastIP >> 16) & 0xff;
    output[19] = (multicastIP >> 24) & 0xff;
    //UDP srcPort=dstPort=520
    output[20] = 0x02;
    output[21] = 0x08;
    output[22] = 0x02;
    output[23] = 0x08;
    //UDP length
    int udp_len = 12 + num * 20;
    output[24] = udp_len >> 8;
    output[25] = udp_len & 0xff;
    //UDP checksum
    output[26] = 0;
    output[27] = 0;
}

void checksum_cal(){
    int cksum = 0;
    output[10] = 0;
    output[11] = 0;

    for(int i = 0; i < 20; i += 2){
        cksum += output[i+1];
        cksum += output[i] << 8;
    }

    while(cksum > 0xffff)
    {
        cksum = (cksum >> 16) + (cksum & 0xffff);
    }

    cksum = (~cksum) & 0xffff;

    output[10] = cksum >> 8;
    output[11] = cksum & 0xff;

    return;
}

int f2(uint32_t n) {
    int num = 0;
    while(n) {
        if(n & 1) num++;
        n >>= 1;
    }
    return num;
}

int main(int argc, char *argv[]) {
  // 0a.
  int res = HAL_Init(1, addrs);
  if (res < 0) {
    return res;
  }

  // 0b. Add direct routes
  // For example:
  // 10.0.0.1/24 if 0
  // 10.0.1.1/24 if 1
  // 10.0.2.1/24 if 2
  // 10.0.3.1/24 if 3
  for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++) {
    RoutingTableEntry entry = {
        .addr = addrs[i] & 0x00ffffff, // big endian
        .len = 24,        // small endian
        .if_index = i,    // small endian
        .nexthop = 0,     // big endian, means direct
        .metric = htonl(1)
    };
    update(true, entry);
  }
    // What to do?
    // send complete routing table to every interface
    // ref. RFC2453 3.8
    // multicast MAC for 224.0.0.9 is 01:00:5e:00:00:09

  uint64_t last_time = 0;
  while (1) {
    uint64_t time = HAL_GetTicks();
    if (time > last_time + 5 * 1000) {
        for(int i = 0; i < N_IFACE_ON_BOARD; i++) {
            RipPacket rippacket;
            int entries_num = 0;
            if(Next[0] == 0){
                printf("路由表为空");
                break;
            }
            int n = Next[0];
            int pre = 0;
            while(n != 0){
                //水平分割，若端口相等，不组播
                if(table[n].if_index == i){
                    pre = n;
                    n = Next[n];
                }else{//若不相等，添加到rippacket中
                    uint32_t mask = 0;
                    for(int j = 0; j < table[n].len; j++){
                        mask = (mask << 1) + 1;
                    }
                    rippacket.entries[entries_num].addr = table[n].addr;
                    rippacket.entries[entries_num].mask = mask;
                    rippacket.entries[entries_num].nexthop = table[n].nexthop;
                    rippacket.entries[entries_num].metric = table[n].metric;
                    entries_num++;
                    pre = n;
                    n = Next[n];
                }
            }
            rippacket.numEntries = entries_num;
            rippacket.command = 2;
            //计算totalLen
            uint32_t totalLen = 32 + 20 * entries_num;
            create_header(totalLen, i, entries_num);
            //计算IP checksum
            checksum_cal();
            assemble(&rippacket, output + 28);
            HAL_SendIPPacket(i, output, totalLen, multicastMac);
        }
        printf("30s Timer\n");
        Show();
        last_time = time;
    }

    int mask = (1 << N_IFACE_ON_BOARD) - 1;
    macaddr_t src_mac;
    macaddr_t dst_mac;
    int if_index;
    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac, dst_mac,
                              1000, &if_index);
    if (res == HAL_ERR_EOF) {
      break;
    } else if (res < 0) {
      return res;
    } else if (res == 0) {
      // Timeout
      continue;
    } else if (res > sizeof(packet)) {
      // packet is truncated, ignore it
      continue;
    }

    // 1. validate
    if (!validateIPChecksum(packet, res)) {
      printf("Invalid IP Checksum\n");
      continue;
    }
    in_addr_t src_addr, dst_addr;
    // extract src_addr and dst_addr from packet
    // big endian
    src_addr = ((uint32_t)packet[15] << 24) + ((uint32_t)packet[14] << 16) + ((uint32_t)packet[13] << 8) + (uint32_t)packet[12];
    dst_addr = ((uint32_t)packet[19] << 24) + ((uint32_t)packet[18] << 16) + ((uint32_t)packet[17] << 8) + (uint32_t)packet[16];

//    printf("addr:%08x\n", src_addr);
//    printf("addr:%08x\n", dst_addr);

    // 2. check whether dst is me
    bool dst_is_me = false;
    for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
      if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0) {
        dst_is_me = true;
        break;
      }
    }
    // TODO: Handle rip multicast address(224.0.0.9)?
    if(memcmp(&dst_addr, &multicastIP, sizeof(in_addr_t)) == 0){
        dst_is_me = true;
    }
    printf("%08x\n", dst_addr);

    if (dst_is_me) {
      // 3a.1
      printf("3a.1\n");
      RipPacket rip;
      // check and validate
      if (disassemble(packet, res, &rip)) {
        printf("command:%d\n", rip.command);
        if (rip.command == 1) {
          // 3a.3 request, ref. RFC2453 3.9.1
          printf("3a.3\n");
          // only need to respond to whole table requests in the lab
          RipPacket resp;
          // TODO: fill resp
          int entries_num = 0;
          if(Next[0] == 0) {
            printf("路由表为空");
          }
          int n = Next[0];
          int pre = 0;
          while(n != 0){
              //水平分割
              if(table[n].if_index == if_index){
                  pre = n;
                  n = Next[n];
                  continue;
              }else{
                  uint32_t mask = 0;
                  for(int j = 0; j < table[n].len; j++){
                      mask = (mask << 1) + 1;
                  }
                  resp.entries[entries_num].addr = table[n].addr;
                  resp.entries[entries_num].mask = mask;
                  resp.entries[entries_num].nexthop = table[n].nexthop;
                  resp.entries[entries_num].metric = table[n].metric;
                  entries_num++;
                  pre = n;
                  n = Next[n];
              }
          }
          resp.numEntries = entries_num;
          resp.command = 2;
          //计算totalLen
          uint32_t totalLen = 20 + 8 + 4 + 20 * entries_num;
          // assemble
          // IP
          output[0] = 0x45;
          //TOS=0
          output[1] = 0;
          //Total Length
          output[2] = totalLen >> 8;
          output[3] = totalLen & 0xff;
          //id=0
          output[4] = 0;
          output[5] = 0;
          //Flags=0 & OFF = 0
          output[6] = 0;
          output[7] = 0;
          //TTL=1
          output[8] = 1;
          //Protocol UDP17
          output[9] = 0x11;
          //source address
          output[12] = addrs[if_index] & 0xff;
          output[13] = (addrs[if_index] >> 8) & 0xff;
          output[14] = (addrs[if_index] >> 16) & 0xff;
          output[15] = (addrs[if_index] >> 24) & 0xff;
          //destination address
          output[16] = src_addr & 0xff;
          output[17] = (src_addr >> 8) & 0xff;
          output[18] = (src_addr >> 16) & 0xff;
          output[19] = (src_addr >> 24) & 0xff;
          // UDP
          // port = 520
          output[20] = 0x02;
          output[21] = 0x08;
          output[22] = 0x02;
          output[23] = 0x08;
          //UDP length
          int udp_len = 12 + entries_num * 20;
          output[24] = udp_len >> 8;
          output[25] = udp_len & 0xff;
          // ...
          // RIP
          uint32_t rip_len = assemble(&resp, &output[20 + 8]);
          // checksum calculation for ip and udp
          checksum_cal();
          // if you don't want to calculate udp checksum, set it to zero
          output[26] = 0;
          output[27] = 0;
          // send it back
          HAL_SendIPPacket(if_index, output, rip_len + 20 + 8, src_mac);
        } else {
          // 3a.2 response, ref. RFC2453 3.9.2
          printf("3a.2\n");
          // update routing table
          // new metric = ?
          // update metric, if_index, nexthop
          // what is missing from RoutingTableEntry?
          // TODO: use query and update
          // triggered updates? ref. RFC2453 3.10.1
          for(int i = 0; i < rip.numEntries; i++){
              printf("%08x ", rip.entries[i].addr);
              printf("%08x ", rip.entries[i].metric);
              printf("%08x ", rip.entries[i].nexthop);
              printf("%08x\n", rip.entries[i].mask);
              int n = Next[0];
              bool not_find = true;
              int pre = 0;
              if(n == 0)
                  printf("路由表为空");
              while(n != 0){
                  int len = f2(rip.entries[i].mask);
                  printf("rip.entries[i].addr:%08x\n", rip.entries[i].addr);
                  printf("table[n].addr:%08x\n", table[n].addr);
                  if(table[n].addr == rip.entries[i].addr && table[n].len == len){
                      printf("find!!!\n");
                      not_find = false;
                      if(if_index == table[n].if_index){
                          printf("same if_index\n");
                          if(ntohl(rip.entries[i].metric) > 15){
                              printf("need delete\n");
                              Next[pre] = Next[n];
                              pre = n;
                              n = Next[n];
                              break;
                          }else{
                              printf("update\n");
                              printf("%d\n", ntohl(rip.entries[i].metric) + 1);
                              printf("%d\n", ntohl(table[n].metric));
                              table[n].metric = ntohl(ntohl(rip.entries[i].metric) + 1);
                              table[n].nexthop = src_addr;
                              pre = n;
                              n = Next[n];
                              break;
                          }
                      }else{
                          printf("not same");
                          if(ntohl(rip.entries[i].metric) + 1 <= ntohl(table[n].metric)){
                              table[n].metric = ntohl(ntohl(rip.entries[i].metric) + 1);
                              table[n].nexthop = src_addr;
                              table[n].if_index = if_index;
                              pre = n;
                              n = Next[n];
                              break;
                          }
                      }
                  }
                  pre = n;
                  n = Next[n];
              }
              if(not_find){
                  printf("not find\n");
                  printf("%08x\n", ntohl(rip.entries[i].metric));
                  if(ntohl(rip.entries[i].metric) <= 15){
                      cnt++;
                      Next[pre] = cnt;
                      table[Next[pre]].addr = rip.entries[i].addr;
                      table[Next[pre]].if_index = if_index;
                      table[Next[pre]].nexthop = src_addr;
                      table[Next[pre]].metric = ntohl(ntohl(rip.entries[i].metric) + 1);
                      int len = f2(rip.entries[i].mask);
                      table[Next[pre]].len = len;
                  }
              }
          }
        }
      }
    } else {
      // 3b.1 dst is not me
      printf("3b.1\n");
      // forward
      // beware of endianness
      uint32_t nexthop, dest_if;
      if (query(dst_addr, &nexthop, &dest_if)) {
        // found
        macaddr_t dest_mac;
        // direct routing
        if (nexthop == 0) {
          nexthop = dst_addr;
        }
        if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0) {
          // found
          memcpy(output, packet, res);
          // update ttl and checksum
          forward(output, res);
          // TODO: you might want to check ttl=0 case
          if(output[8] == 0){
              continue;
          }
          HAL_SendIPPacket(dest_if, output, res, dest_mac);
        } else {
          // not found
          // you can drop it
          printf("ARP not found for %x\n", nexthop);
        }
      } else {
        // not found
        // optionally you can send ICMP Host Unreachable
        printf("IP not found for %x\n", src_addr);
      }
    }
  }
  return 0;
}
