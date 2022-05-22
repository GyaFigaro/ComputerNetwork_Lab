#include <string.h>
#include <stdio.h>
#include "net.h"
#include "arp.h"
#include "ethernet.h"
/**
 * @brief 初始的arp包
 * 
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = swap16(ARP_HW_ETHER),
    .pro_type16 = swap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 * 
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 * 
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 * 
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp)
{
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 * 
 */
void arp_print()
{
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 * 
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip)
{
    // TO-DO
    uint8_t boardcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t mac0[6] = {0,0,0,0,0,0};
    buf_init(&txbuf, sizeof(arp_pkt_t));                     //初始化 
    arp_pkt_t *pkt = (arp_pkt_t *)(txbuf.data);

    //填写报头
    *pkt = arp_init_pkt;
    pkt->opcode16 = swap16(ARP_REQUEST);
    memcpy(pkt->target_ip, target_ip, sizeof(NET_IP_LEN));                      
    memcpy(pkt->target_mac, mac0, sizeof(NET_MAC_LEN));

    ethernet_out(&txbuf, boardcast_mac, NET_PROTOCOL_ARP);    //发送报文
}

/**
 * @brief 发送一个arp响应
 * 
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac)
{
    // TO-DO
    buf_init(&txbuf, sizeof(arp_pkt_t));                 //初始化
    arp_pkt_t *pkt = (arp_pkt_t *)(txbuf.data);
    
    //填写报头
    *pkt = arp_init_pkt;
    pkt->opcode16 = swap16(ARP_REPLY);
    memcpy(pkt->target_ip, target_ip, sizeof(NET_IP_LEN));                     
    for(int i = 0; i < NET_MAC_LEN; i++){
        pkt->target_mac[i] = target_mac[i];
    }
    ethernet_out(&txbuf, target_mac, NET_PROTOCOL_ARP);   //发送报文
}

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac)
{
    // TO-DO
    arp_pkt_t *pkt = (arp_pkt_t *)(buf->data);

    //判断数据包长度和arp报头信息是否合法
    if(buf->len < sizeof(arp_pkt_t) 
       || pkt->hw_type16 != swap16(ARP_HW_ETHER) 
       || pkt->pro_type16 != swap16(NET_PROTOCOL_IP) 
       || pkt->hw_len != NET_MAC_LEN
       || pkt->pro_len != NET_IP_LEN
       || (pkt->opcode16 != swap16(ARP_REPLY) && pkt->opcode16 != swap16(ARP_REQUEST))){
        return;
    }

    buf_t *old_buf = NULL;                                  //map表里原有的buf地址；
    uint8_t *src_ip = pkt->sender_ip;
    map_set(&arp_table, src_ip, src_mac);                   //记入arp表
    old_buf = map_get(&arp_buf, src_ip);                    //从arp_buf中获取缓存
    if(old_buf != NULL){                                    //存在数据包
        ethernet_out(old_buf, src_mac, NET_PROTOCOL_IP);    //则发送到以太网
        map_delete(&arp_buf, src_ip);                       //并移除
    }
    else{                                                   //不存在数据包
        if(pkt->opcode16 == swap16(ARP_REQUEST)             
           && (memcmp(pkt->target_ip, net_if_ip, NET_IP_LEN)) == 0){
            arp_resp(src_ip, src_mac);                      //发送arp回复
        }
    }
}

/**
 * @brief 处理一个要发送的数据包
 * 
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void arp_out(buf_t *buf, uint8_t *ip)
{
    // TO-DO
    uint8_t *dst_mac = map_get(&arp_table, ip);          //从arp表中获得目标mac
    if(dst_mac != NULL){                                 //获得即发出
        ethernet_out(buf, dst_mac, NET_PROTOCOL_IP);     
    }
    else{                                                //为空
        if(arp_buf.size == 0){                           //且对应arp_buf为空
            map_set(&arp_buf, ip, buf);                  //则部署进arp_buf
            arp_req(ip);                                 //并发送arp请求
        }
    }
}

/**
 * @brief 初始化arp协议
 * 
 */
void arp_init()
{
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL);
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, buf_copy);
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}