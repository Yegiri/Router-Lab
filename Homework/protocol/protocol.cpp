#include "rip.h"
#include <stdint.h>
#include <stdlib.h>
#include <iostream>
#include <stdio.h>
using namespace std;

/*
  在头文件 rip.h 中定义了如下的结构体：
  #define RIP_MAX_ENTRY 25
  typedef struct {
    // all fields are big endian
    // we don't store 'family', as it is always 2(for response) and 0(for request)
    // we don't store 'tag', as it is always 0
    uint32_t addr;
    uint32_t mask;
    uint32_t nexthop;
    uint32_t metric;
  } RipEntry;

  typedef struct {
    uint32_t numEntries;
    // all fields below are big endian
    uint8_t command; // 1 for request, 2 for response, otherwsie invalid
    // we don't store 'version', as it is always 2
    // we don't store 'zero', as it is always 0
    RipEntry entries[RIP_MAX_ENTRY];
  } RipPacket;

  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的 IP 包
  由于 Rip 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在 RipPacket 中额外记录了个数。
  需要注意这里的地址都是用 **大端序** 存储的，1.2.3.4 对应 0x04030201 。
*/

void add(const uint8_t *packet, RipPacket *p, int order){
    p->entries[order].addr = (packet[39 + order * 20] << 24) + (packet[38 + order * 20] << 16) + (packet[37 + order * 20] << 8) + packet[36 + order * 20];
    p->entries[order].mask = (packet[43 + order * 20] << 24) + (packet[42 + order * 20] << 16) + (packet[41 + order * 20] << 8) + packet[40 + order * 20];
    p->entries[order].nexthop = (packet[47 + order * 20] << 24) + (packet[46 + order * 20] << 16) + (packet[45 + order * 20] << 8) + packet[44 + order * 20];
    p->entries[order].metric = (packet[51 + order * 20] << 24) + (packet[50 + order * 20] << 16) + (packet[49 + order * 20] << 8) + packet[48 + order * 20];
}

/**
 * @brief 从接受到的 IP 包解析出 Rip 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回 true；否则返回 false
 * 
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len 时，把传入的 IP 包视为不合法。
 * 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系（见上面结构体注释），Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
  // TODO:
    RipPacket test;
    int headLen = (packet[0] & 0xf) * 4;
    int totalLen = (packet[2] << 8) + packet[3];
    if(totalLen > len)
        return false;
    int command = packet[28];
    int version = packet[29];
    int zero = (packet[30] << 8) + packet[31];
    int metric = (packet[48] << 24) + (packet[49] << 16) + (packet[50] << 8) + packet[51];
    int mask0 = packet[40];
    int mask1 = packet[41];
    int mask2 = packet[42];
    int mask3 = packet[43];
    if(!(mask0 == 0 || mask0 == 0xff) || !(mask1 == 0 || mask1 == 0xff) || !(mask2 == 0 || mask2 == 0xff) || !(mask3 == 0 || mask3 == 0xff))
        return false;
    if(command != 1 && command != 2)
        return false;
    if(version != 2)
        return false;
    if(zero != 0)
        return false;
    int family = (packet[32] << 8) + packet[33];
    if(!((command == 1 && family == 0) || (command == 2 && family == 2)))
        return false;
    int tag = (packet[34] << 8) + packet[35];
    if(tag != 0)
        return false;
    if(!(metric>=1 && metric<=16))
        return false;
    test.numEntries = (len - 32) / 20;
    test.command = command;
    for(int i = 0; i < test.numEntries; i++)
        add(packet, &test, i);
//    test.entries[0].addr = (packet[39] << 24) + (packet[38] << 16) + (packet[37] << 8) + packet[36];
//    test.entries[0].mask = (packet[43] << 24) + (packet[42] << 16) + (packet[41] << 8) + packet[40];
//    test.entries[0].nexthop = (packet[47] << 24) + (packet[46] << 16) + (packet[45] << 8) + packet[44];
//    test.entries[0].metric = (packet[51] << 24) + (packet[50] << 16) + (packet[49] << 8) + packet[48];
    *output = test;
    return true;
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 * 
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括 Version、Zero、Address Family 和 Route Tag 这四个字段
 * 你写入 buffer 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
uint32_t assemble(const RipPacket *rip, uint8_t *buffer) {
  // TODO:
  buffer[0] = rip->command;
  buffer[1] = 2;
  buffer[2] = 0;
  buffer[3] = 0;
//  printf("%d\n", rip->numEntries);
  for(int i = 0; i < rip->numEntries; i++){
    buffer[4 + i*20] = 0;
    if(rip->command == 1)
        buffer[5 + i*20] = 0;
    else
        buffer[5 + i*20] = 2;
    buffer[6 + i*20] = 0;
    buffer[7 + i*20] = 0;
    //addr
    buffer[8 + i*20] = rip->entries[i].addr & 0x000000ff;
    buffer[9 + i*20] = (rip->entries[i].addr >> 8) & 0x000000ff;
    buffer[10 + i*20] = (rip->entries[i].addr >> 16) & 0x000000ff;
    buffer[11 + i*20] = (rip->entries[i].addr >> 24) & 0x000000ff;
    //mask
    buffer[12 + i*20] = rip->entries[i].mask & 0x000000ff;
    buffer[13 + i*20] = (rip->entries[i].mask >> 8) & 0x000000ff;
    buffer[14 + i*20] = (rip->entries[i].mask >> 16) & 0x000000ff;
    buffer[15 + i*20] = (rip->entries[i].mask >> 24) & 0x000000ff;
    //nexthop
    buffer[16 + i*20] = rip->entries[i].nexthop & 0x000000ff;
    buffer[17 + i*20] = (rip->entries[i].nexthop >> 8) & 0x000000ff;
    buffer[18 + i*20] = (rip->entries[i].nexthop >> 16) & 0x000000ff;
    buffer[19 + i*20] = (rip->entries[i].nexthop >> 24) & 0x000000ff;
    //metric
    buffer[20 + i*20] = rip->entries[i].metric & 0x000000ff;
    buffer[21 + i*20] = (rip->entries[i].metric >> 8) & 0x000000ff;
    buffer[22 + i*20] = (rip->entries[i].metric >> 16) & 0x000000ff;
    buffer[23 + i*20] = (rip->entries[i].metric >> 24) & 0x000000ff;
  }
  return 24 + (rip->numEntries - 1) * 20;
}
