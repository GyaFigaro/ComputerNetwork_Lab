#include "net.h"
#include "icmp.h"
#include "ip.h"

/**
 * @brief 发送icmp响应
 * 
 * @param req_buf 收到的icmp请求包
 * @param src_ip 源ip地址
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip)
{
    // TO-DO
    uint16_t check_sum;

    //初始化txbuf并将请求报文复制进去
    buf_init(&txbuf, req_buf->len);
    memcpy(txbuf.data, req_buf->data, req_buf->len);

    //封装并填写icmp头部
    icmp_hdr_t *icmp_resp_head = (icmp_hdr_t *)(txbuf.data);
    icmp_resp_head->code = 0;
    icmp_resp_head->type = ICMP_TYPE_ECHO_REPLY;
    icmp_resp_head->checksum16 = 0;

    //计算并填写校验和
    check_sum = checksum16((uint16_t *)(txbuf.data), (txbuf.len / 2));
    icmp_resp_head->checksum16 = swap16(check_sum);

    //调用ip_out发送icmp报文
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip)
{
    // TO-DO
    //若长度不合法（小于icmp头部类型长度）
    if (buf->len < sizeof(icmp_hdr_t)){
        return;
    }

    //若为icmp请求报文则回复一个icmp回复报文
    icmp_hdr_t *icmp_head = (icmp_hdr_t *)(buf->data);
    if (icmp_head->type == ICMP_TYPE_ECHO_REQUEST){
        icmp_resp(buf, src_ip);
    }
}

/**
 * @brief 发送icmp不可达
 * 
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code)
{
    // TO-DO
    uint16_t check_sum;

    //初始化txbuf并将ip报头及其后8个字节的数据复制进去。
    buf_init(&txbuf, sizeof(ip_hdr_t) + 8);
    memcpy(txbuf.data, recv_buf->data, sizeof(ip_hdr_t) + 8);

    //添加、封装并填写icmp报头
    buf_add_header(&txbuf, sizeof(icmp_hdr_t));
    icmp_hdr_t *icmp_head = (icmp_hdr_t *)(txbuf.data);
    icmp_head->code = code;
    icmp_head->type = ICMP_TYPE_UNREACH;
    icmp_head->checksum16 = 0;
    icmp_head->id16 = 0;
    icmp_head->seq16 = 0;

    //计算并填写校验和
    check_sum = checksum16((uint16_t *)(txbuf.data), (txbuf.len / 2));
    icmp_head->checksum16 = swap16(check_sum);

    //调用ip_out发送icmp报文
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 初始化icmp协议
 * 
 */
void icmp_init(){
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}