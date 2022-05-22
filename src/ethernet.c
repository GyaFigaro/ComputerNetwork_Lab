#include "ethernet.h"
#include "utils.h"
#include "driver.h"
#include "arp.h"
#include "ip.h"
/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 */
void ethernet_in(buf_t *buf)
{
    // TO-DO
    uint8_t src[NET_MAC_LEN];
    uint16_t prot;
    if(buf->len < sizeof(ether_hdr_t)){                    //判断长度是否合法
        return;
    }
    ether_hdr_t *hdr = (ether_hdr_t *)(buf->data);
    for(int i = 0; i < 6; i++){                            //获取mac
         src[i] = hdr->src[i];
    }
    prot = hdr->protocol16;                                //获取协议类型
    buf_remove_header(buf, sizeof(ether_hdr_t));           //移除eth报头
    if(prot == swap16(NET_PROTOCOL_IP))
       net_in(buf, NET_PROTOCOL_IP, src);
    if(prot == swap16(NET_PROTOCOL_ARP))
       net_in(buf, NET_PROTOCOL_ARP, src);
}
/**
 * @brief 处理一个要发送的数据包
 * 
 * @param buf 要处理的数据包
 * @param mac 目标MAC地址
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol)
{
    // TO-DO
    if(buf->len < 46){                                  //添加pad
        buf_add_padding(buf, 46 - buf->len);
    }
    buf_add_header(buf, sizeof(ether_hdr_t));           //添加eth报头
    ether_hdr_t *hdr = (ether_hdr_t *)(buf->data);
    for(int i = 0; i < 6; i++){                         //写入mac信息
        hdr->dst[i] = mac[i];
        hdr->src[i] = net_if_mac[i];
    }
    hdr->protocol16 = swap16(protocol);                 //写入上层协议
    driver_send(buf);                                   //网卡发送到驱动层
}
/**
 * @brief 初始化以太网协议
 * 
 */
void ethernet_init()
{
    buf_init(&rxbuf, ETHERNET_MAX_TRANSPORT_UNIT + sizeof(ether_hdr_t));
}

/**
 * @brief 一次以太网轮询
 * 
 */
void ethernet_poll()
{
    if (driver_recv(&rxbuf) > 0)
        ethernet_in(&rxbuf);
}
