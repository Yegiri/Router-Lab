#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <typeinfo>

/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len) {
  // TODO:
    int length = (packet[0] & 0xf) * 4;

    int buf1 = packet[10];
    int buf2 = packet[11];
    int buf = (buf1 << 8) + buf2;

    unsigned int cksum = 0;

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

	cksum = (~cksum) & 0xffff;

	packet[10] = buf1;
	packet[11] = buf2;

	if(cksum == buf)
	    return true;
	else
	    return false;
}

