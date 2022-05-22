#include "net.h"
#include "ip.h"
#include "ethernet.h"
#include "arp.h"
#include "icmp.h"

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac)
{
    // TO-DO
    uint16_t check_sum, sum;
    uint8_t src_ip[4], prot;

    //若长度不合法（小于ip头部类型长度）则弃置
    if (buf->len < sizeof(ip_hdr_t))  return;

    ip_hdr_t *ip_head = (ip_hdr_t *)(buf->data);

    //若版本号不为IPv4或头部中的数据包长度与数据包实际大小不相等，则弃置
    if (ip_head->version != 4 || ip_head->total_len16 > swap16(buf->len)){
        return;
    }

    //计算校验和，若结果与报头中的校验和不同，则弃置
    check_sum = ip_head->hdr_checksum16;
    ip_head->hdr_checksum16 = 0;
    sum = checksum16((uint16_t *)ip_head, 10);
    if (check_sum != swap16(sum))  return;
    else {
        ip_head->hdr_checksum16 = check_sum;
    }

    //若目的ip不为本机ip，则弃置
    if (memcmp(ip_head->dst_ip, net_if_ip, NET_IP_LEN) != 0) return;
    if (buf->len > swap16(ip_head->total_len16)){
        buf_remove_padding(buf, buf->len - swap16(ip_head->total_len16));
    }

    //获得源ip地址
    for (int i = 0; i < NET_IP_LEN; i++)
    {
        src_ip[i] = ip_head->src_ip[i];
    }

    //按上层协议去除ip报头后发送数据包
    prot = ip_head->protocol;
    switch (prot)
    {
    case NET_PROTOCOL_UDP:
        buf_remove_header(buf, sizeof(ip_hdr_t));
        net_in(buf, NET_PROTOCOL_UDP, src_ip);
        break;
    case NET_PROTOCOL_ICMP:
        buf_remove_header(buf, sizeof(ip_hdr_t));
        net_in(buf, NET_PROTOCOL_ICMP, src_ip);
        break;
    default: 
        //若为无法识别的协议类型，则不用去除报头
        //直接发送icmp协议不可达差错报文
        icmp_unreachable(buf, src_ip, ICMP_CODE_PROTOCOL_UNREACH);
        break;
    }
}

/**
 * @brief 处理一个要发送的ip分片
 * 
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf)
{
    // TO-DO
    uint16_t check_sum;

    //添加并封装IP报头
    buf_add_header(buf, sizeof(ip_hdr_t));
    ip_hdr_t *ip_head = (ip_hdr_t *)(buf->data);

    //填写IP报头
    for (int i = 0; i < NET_IP_LEN; i++)
    {
        ip_head->dst_ip[i] = ip[i];
        ip_head->src_ip[i] = net_if_ip[i];
    }
    ip_head->protocol = protocol;
    ip_head->id16 = swap16(id);
    ip_head->hdr_len = 5;
    ip_head->version = IP_VERSION_4;
    ip_head->ttl = IP_DEFALUT_TTL;
    ip_head->tos = 0;
    ip_head->hdr_checksum16 = 0;
    ip_head->total_len16 = swap16(buf->len);

    //偏移量除以8，并加上左移13位的mf（是否分片信息）
    ip_head->flags_fragment16 = 
        swap16((offset / IP_HDR_OFFSET_PER_BYTE) + ((mf) ? IP_MORE_FRAGMENT : 0));
    
    //填写校验和
    check_sum = checksum16((uint16_t *)ip_head, 10);
    ip_head->hdr_checksum16 = swap16(check_sum);

    //通过arp发送出去
    arp_out(buf, ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 * 
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
    // TO-DO
    static int id = 0;          //id计数器

    //如果小于（MTU - ip首部长度）则直接作为一片发送
    if (buf->len <= 1500 - sizeof(ip_hdr_t)){
        ip_fragment_out(buf, ip, protocol, id++, 0, 0);
    }

    //否则进行分片
    else {
        buf_t ip_buf;
        int cnt = 0;                          //片数计数器
        int ip_data_len = 1480;               //MTU
        int ip_rest_len = buf->len;           //原数据包剩余长度

        while (ip_rest_len > ip_data_len){
            buf_init(&ip_buf, ip_data_len);
            memcpy(ip_buf.data, buf->data + (ip_data_len * cnt), ip_data_len);
            ip_fragment_out(&ip_buf, ip, protocol, id, 
                            cnt * ip_data_len, 1);
            ip_rest_len -= ip_data_len;
            cnt++;
        }

        //最后一片
        buf_init(&ip_buf, ip_rest_len);
        memcpy(ip_buf.data, buf->data + (ip_data_len * cnt), ip_rest_len);
        ip_fragment_out(&ip_buf, ip, protocol, id++, cnt * ip_data_len, 0);
    }
}

/**
 * @brief 初始化ip协议
 * 
 */
void ip_init()
{
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}