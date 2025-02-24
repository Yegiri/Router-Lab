#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以从 checksum 题中复制代码到这里使用。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool forward(uint8_t *packet, size_t len) {
  // TODO:
    int length = (packet[0] & 0xf) * 4;
    uint16_t buf = ((uint32_t)packet[10] << 8) | packet[11];

    uint32_t cksum = 0;

    packet[10] = 0;
    packet[11] = 0;

    for(int i = 0; i < length; i += 2){
        cksum += packet[i + 1];
	    cksum += (uint32_t)packet[i] << 8;
    }

    while(cksum > 0xffff)
    {
        cksum = (cksum >> 16) + (cksum & 0xffff);
    }

    uint16_t ans = (~cksum) & 0xffff;
    //printf("checksum: %04x, buf: %04x\n", ans, buf);
    if(ans != buf){
	//printf("false\n");
        return false;
    }
    else{
        packet[8] -= 1;

        cksum = 0;

        for(int i = 0; i < length; i += 2){
            cksum += packet[i + 1];
            cksum += (uint32_t)packet[i] << 8;
        }

        while(cksum > 0xffff)
        {
            cksum = (cksum >> 16) + (cksum & 0xffff);
        }

        cksum = (~cksum) & 0xffff;

        packet[10] = cksum >> 8;
        packet[11] = cksum & 0xff;

        return true;
    }
}
