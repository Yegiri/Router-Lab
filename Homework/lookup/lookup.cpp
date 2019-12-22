#include "router.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <iostream>
using namespace std;

/*
  RoutingTable Entry 的定义如下：
  typedef struct {
    uint32_t addr; // 大端序，IPv4 地址
    uint32_t len; // 小端序，前缀长度
    uint32_t if_index; // 小端序，出端口编号
    uint32_t nexthop; // 大端序，下一跳的 IPv4 地址
  } RoutingTableEntry;

  约定 addr 和 nexthop 以 **大端序** 存储。
  这意味着 1.2.3.4 对应 0x04030201 而不是 0x01020304。
  保证 addr 仅最低 len 位可能出现非零。
  当 nexthop 为零时这是一条直连路由。
  你可以在全局变量中把路由表以一定的数据结构格式保存下来。
*/

RoutingTableEntry table[4096];
int Next[4096];
int cnt = 1;

void insertList(RoutingTableEntry entry){
    //如果链表为空，直接添加元素至表头
    if(Next[0] == 0){
        Next[0] = cnt;
        table[Next[0]] = entry;
    }else{
        int n = Next[0];
        int pre = 0;
        while(n != 0){
            if(table[n].addr == entry.addr && table[n].len == entry.len) {
                if(entry.metric + 1 <= table[n].metric){
                    table[n].metric = entry.metric + 1;
                    return;
                }else{
                    return;
                }
            }
            pre = n;
            n = Next[n];
        }
        cnt++;
        Next[pre] = cnt;
        table[Next[pre]] = entry;
    }
}

void deleteList(RoutingTableEntry entry){
    if(Next[0] == 0)
        return;
    int pre = 0;
    int n = Next[0];
    while(n != 0){
        if(table[n].addr == entry.addr && table[n].len == entry.len) {
            Next[pre] = Next[n];
            return;
        }
        if(Next[n] == 0)
            return;
        else{
            pre = n;
            n = Next[n];
        }
    }
}

void Show(){
    if(Next[0] == 0){
        cout << "链表为空" << endl;
        return;
    }
    else{
        int n = Next[0];
        while(n != 0){
            printf("addr:%08x ", table[n].addr);
            printf("len:%d ", table[n].len);
            printf("metric:%08x ", table[n].metric);
            printf("nexthop:%08x ", table[n].nexthop);
            printf("if_index:%d\n", table[n].if_index);
            if(Next[n] == 0)
                return;
            else
                n = Next[n];
        }
    }
}

/**
 * @brief 插入/删除一条路由表表项
 * @param insert 如果要插入则为 true ，要删除则为 false
 * @param entry 要插入/删除的表项
 * 
 * 插入时如果已经存在一条 addr 和 len 都相同的表项，则替换掉原有的。
 * 删除时按照 addr 和 len 匹配。
 */
void update(bool insert, RoutingTableEntry entry) {
    // TODO:
    if(insert){   //插入
        insertList(entry);
    }else{    //删除
        deleteList(entry);
    }
//    Show();
//    printf("\n");
}

/**
 * @brief 进行一次路由表的查询，按照最长前缀匹配原则
 * @param addr 需要查询的目标地址，大端序
 * @param nexthop 如果查询到目标，把表项的 nexthop 写入
 * @param if_index 如果查询到目标，把表项的 if_index 写入
 * @return 查到则返回 true ，没查到则返回 false
 */
bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index) {
    // TODO:
    int ansId = 0, maxLen = 0;
//    printf("%08x ", addr);
    if(Next[0] == 0){
        return false;
    }
    else{
        ansId = 0, maxLen = 0;
        int n = Next[0];
        while(n != 0){
//            printf("%08x ", table[n].nexthop);
//            printf("%d\n", table[n].if_index);
//            printf("len: %d\n", table[n].len);
            if(table[n].len == 24){
//                printf("table: %08x\n", table[n].addr & 0x00ffffff);
//                printf("addr: %08x\n", addr & 0x00ffffff);
                if((table[n].addr & 0x00ffffff) == (addr & 0x00ffffff)){
//                    printf("enter 24\n");
                    if(table[n].len > maxLen){
                        maxLen = table[n].len;
                        ansId = n;
                    }
                }
            }else if(table[n].len == 32){
//                printf("table: %08x\n", table[n].addr & 0xffffffff);
//                printf("addr: %08x\n", addr & 0xffffffff);
                if((table[n].addr & 0xffffffff) == (addr & 0xffffffff)){
//                    printf("enter 32\n");
                    if(table[n].len > maxLen){
                        maxLen = table[n].len;
                        ansId = n;
                    }
                }
            }
//            printf("ansId: %d\n", ansId);
//            printf("\n");
            n = Next[n];
        }
        if(ansId != 0){
//            printf("enter\n");
//            table[ansId].if_index = *if_index;
//            table[ansId].nexthop = *nexthop;
            *if_index = table[ansId].if_index;
            *nexthop = table[ansId].nexthop;
            return true;
        } else
            return false;
    }
}
