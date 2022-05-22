#include "udp.h"
#include "ip.h"
#include "icmp.h"

/**
 * @brief udp处理程序表
 * 
 */
map_t udp_table;

/**
 * @brief udp伪校验和计算
 * 
 * @param buf 要计算的包
 * @param src_ip 源ip地址
 * @param dst_ip 目的ip地址
 * @return uint16_t 伪校验和
 */
static uint16_t udp_checksum(buf_t *buf, uint8_t *src_ip, uint8_t *dst_ip)
{
    // TO-DO
    uint16_t sum, buf_checksum_len_is_odd;

    //拷贝ip报头部分，防止被udp伪头部覆盖
    ip_hdr_t ip_head;
    memcpy(&ip_head, (buf->data - sizeof(ip_hdr_t)), sizeof(ip_hdr_t));

    //添加、封装并填写udp伪头部
    buf_add_header(buf, sizeof(udp_peso_hdr_t));
    udp_peso_hdr_t *udp_phdr = (udp_peso_hdr_t *)(buf->data);
    for (int i = 0; i < NET_IP_LEN; i++){
        udp_phdr->dst_ip[i] = dst_ip[i];
        udp_phdr->src_ip[i] = src_ip[i];
    }
    udp_phdr->protocol = NET_PROTOCOL_UDP;
    udp_phdr->placeholder = 0;
    udp_phdr->total_len16 = swap16(buf->len - sizeof(udp_peso_hdr_t));

    //计算校验和
    buf_checksum_len_is_odd = buf->len % 2;
    if (buf_checksum_len_is_odd){        //若数据包长度为奇数
        buf_add_padding(buf, 1);         //则在数据包末尾填充一个字节的0
    }
    sum = checksum16((uint16_t *)(buf->data), (buf->len) / 2);

    //去除udp伪头部
    buf_remove_header(buf, sizeof(udp_peso_hdr_t));

    //将ip头部内容拷贝回来
    memcpy((buf->data - sizeof(ip_hdr_t)), &ip_head, sizeof(ip_hdr_t));

    //若上面填充了0，则把它去掉。
    if (buf_checksum_len_is_odd){      
        buf_remove_padding(buf, 1);
    }
    return sum;
}

/**
 * @brief 处理一个收到的udp数据包
 * 
 * @param buf 要处理的包
 * @param src_ip 源ip地址
 */
void udp_in(buf_t *buf, uint8_t *src_ip)
{
    // TO-DO
    //若长度不合法（小于udp头部类型长度）
    if (buf->len < sizeof(udp_hdr_t)){
        return;
    }

    //封装udp头部
    udp_hdr_t *udp_head = (udp_hdr_t *)(buf->data);
    uint16_t check_sum, sum, src_port, dst_port;

    //若数据包实际长度小于udp报头中的总长度，则弃置
    if (buf->len < swap16(udp_head->total_len16)){
        return;
    }

    //获得目的端口和源端口
    src_port = swap16(udp_head->src_port16);
    dst_port = swap16(udp_head->dst_port16);

    //计算udp校验和，若结果与udp报头中的校验和不同，则弃置
    check_sum = udp_head->checksum16;
    udp_head->checksum16 = 0;
    sum = udp_checksum(buf, src_ip, net_if_ip);
    if (check_sum != swap16(sum))  return;
    else {
        udp_head->checksum16 = check_sum;
    }

    //从udp_table中按目的端口获得对应处理函数
    udp_handler_t *handler = map_get(&udp_table, &dst_port);    
    if (handler == NULL){        //没有找到
        buf_add_header(buf, sizeof(ip_hdr_t));             //添加IP数据报头部
        icmp_unreachable(buf, src_ip, ICMP_CODE_PORT_UNREACH);  //发送一个端口不可达的ICMP差错报文
    }
    else {                       //能找到
        buf_remove_header(buf, sizeof(udp_hdr_t));        //则去掉UDP报头。
        (*handler)((uint8_t *)buf->data, buf->len, src_ip, src_port);   //调用处理函数来做相应处理
    }
}

/**
 * @brief 处理一个要发送的数据包
 * 
 * @param buf 要处理的包
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_out(buf_t *buf, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port)
{
    // TO-DO
    uint16_t check_sum;

    //添加、封装udp头部
    buf_add_header(buf, sizeof(udp_hdr_t));
    udp_hdr_t *udp_head = (udp_hdr_t *)(buf->data);

    //填写udp头部信息
    udp_head->src_port16 = swap16(src_port);
    udp_head->dst_port16 = swap16(dst_port);
    udp_head->total_len16 = swap16(buf->len);
    udp_head->checksum16 = 0;

    //计算并填写校验和
    check_sum = udp_checksum(buf, net_if_ip, dst_ip);
    udp_head->checksum16 = swap16(check_sum);

    //调用ip_out将数据包发送出去
    ip_out(buf, dst_ip, NET_PROTOCOL_UDP);
}

/**
 * @brief 初始化udp协议
 * 
 */
void udp_init()
{
    map_init(&udp_table, sizeof(uint16_t), sizeof(udp_handler_t), 0, 0, NULL);
    net_add_protocol(NET_PROTOCOL_UDP, udp_in);
}

/**
 * @brief 打开一个udp端口并注册处理程序
 * 
 * @param port 端口号
 * @param handler 处理程序
 * @return int 成功为0，失败为-1
 */
int udp_open(uint16_t port, udp_handler_t handler)
{
    return map_set(&udp_table, &port, &handler);
}

/**
 * @brief 关闭一个udp端口
 * 
 * @param port 端口号
 */
void udp_close(uint16_t port)
{
    map_delete(&udp_table, &port);
}

/**
 * @brief 发送一个udp包
 * 
 * @param data 要发送的数据
 * @param len 数据长度
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_send(uint8_t *data, uint16_t len, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port)
{
    buf_init(&txbuf, len);
    memcpy(txbuf.data, data, len);
    udp_out(&txbuf, src_port, dst_ip, dst_port);
}