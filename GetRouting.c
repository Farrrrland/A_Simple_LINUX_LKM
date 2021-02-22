#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/net.h>
#include <linux/time.h>
#include <linux/skbuff.h>
#include <linux/if_vlan.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/sched.h>
#include <linux/netlink.h>

#include <net/ip.h>
#include <net/tcp.h>
#include <net/icmp.h>
#include <net/protocol.h>
#include <net/sock.h>
#include <net/net_namespace.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Farland233");

// 将IP地址转化为点分十进制
#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

#define NETLINK_TEST 17         //自定义的协议
#define MAX_PAYLOAD 1024
#define ROUTING_INFO_LEN 100

//函数声明
unsigned int kern_inet_add2num(char *ip_str);
void kern_inet_num2add(char *ip_str , unsigned int ip_num);
unsigned int getRoutingInfo(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
static void nl_data_ready(struct sk_buff *skb);
int netlink_to_user(char *msg, int len);

//hook函数信息
static struct nf_hook_ops nfho = {  
    .hook = getRoutingInfo,         //回调函数
    .pf = PF_INET,  
    .hooknum = NF_INET_LOCAL_OUT,   //Packets coming from a local process
    .priority = NF_IP_PRI_FIRST,    // INT_MIN
}; 
//用于描述Netlink处理函数信息
struct netlink_kernel_cfg cfg = {
    .input = nl_data_ready,
};

static struct sock *nl_sk = NULL;   //用于标记netlink
static int userpid = -1;            //用于存储用户程序的pid
static unsigned int filterip = 0;   //用于存储需要过滤的源IP，小端格式


//回调函数，处理本机发出的数据包
unsigned int getRoutingInfo(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *ip = ip_hdr(skb);
    struct tcphdr *tcph;
    struct udphdr *udph;
    int header = 0;
    char routingInfo[ROUTING_INFO_LEN] = {0};
    //检查ip地址
    if(ntohl(ip->saddr) == filterip){
        printk("=======START========");
        printk("srcIP: %u.%u.%u.%u\n", NIPQUAD(ip->saddr));
        printk("dstIP: %u.%u.%u.%u\n", NIPQUAD(ip->daddr));

        //判断传输层协议
        if(ip->protocol == IPPROTO_TCP){
            tcph = tcp_hdr(skb);
            if(skb->len-header>0){
                printk("srcPORT: %d\n", ntohs(tcph->source));
                printk("dstPORT: %d\n", ntohs(tcph->dest));
                printk("PROTOCOL: TCP");
                sprintf(routingInfo, 
                    "srcIP: %u.%u.%u.%u dstIP: %u.%u.%u.%u srcPORT: %d dstPORT: %d PROTOCOL: TCP", 
                    NIPQUAD(ip->saddr), 
                    NIPQUAD(ip->daddr), 
                    ntohs(tcph->source), 
                    ntohs(tcph->dest));
                netlink_to_user(routingInfo, ROUTING_INFO_LEN);
            }
        }else if(ip->protocol == IPPROTO_UDP){
            udph = udp_hdr(skb);
            if(skb->len-header>0){
                printk("srcPORT:%d\n", ntohs(udph->source));
                printk("dstPORT:%d\n", ntohs(udph->dest));
                printk("PROTOCOL: UDP");
                sprintf(routingInfo, 
                    "srcIP: %u.%u.%u.%u dstIP: %u.%u.%u.%u srcPORT: %d dstPORT: %d PROTOCOL: UDP", 
                    NIPQUAD(ip->saddr), 
                    NIPQUAD(ip->daddr), 
                    ntohs(udph->source), 
                    ntohs(udph->dest));
                netlink_to_user(routingInfo, ROUTING_INFO_LEN);
            }
        }
        printk("========End=========");
    }
    return NF_ACCEPT;
}

//内核端向用户发送消息
int netlink_to_user(char *msg, int len){
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    //创建skb
    skb = nlmsg_new(MAX_PAYLOAD, GFP_ATOMIC);
    if(!skb){
        printk(KERN_ERR"FAILED TO ALLOC SKB\n");
        return -1;
    }
    //对nlh进行初始化
    nlh = nlmsg_put(skb, 0, 0, 0, MAX_PAYLOAD, 0);
    printk("Kernel is sending routing infomation to client %d.\n", userpid);
    
    //发送信息
    memcpy(NLMSG_DATA(nlh), msg, len);
    if(netlink_unicast(nl_sk, skb, userpid, MSG_DONTWAIT) < 0){    //非阻塞，防止内核忙等
        printk(KERN_ERR"FAILED TO SEND SKB\n\n");
        //恢复初始状态
        filterip = 0;
        userpid = -1;
        return -1;
    }
    return 0;
}

//处理kernel接收到的skb消息
static void nl_data_ready(struct sk_buff *skb){
    struct nlmsghdr *nlh = NULL;
    if(skb == NULL){
        printk("INVALID SKB\n");
        return;
    }
    nlh = (struct nlmsghdr *)skb->data;
    printk("Kernel is receiving message from client %d: %s\n", nlh->nlmsg_pid, (char *)NLMSG_DATA(nlh));
    
    filterip = kern_inet_add2num((char *)NLMSG_DATA(nlh));
    userpid=nlh->nlmsg_pid;
}

//将client发来的点分十进制字符串ip地址转化为小端数字ip地址
unsigned int kern_inet_add2num(char *ip_str){
    unsigned int val = 0, part = 0;
    char c;
    int i=0;
    for( ; i<4; i++){
        part = 0;
        while ((c=*ip_str++)!='\0' && c != '.'){
            if(c < '0' || c > '9') return -1;   //非法格式（非数）
            part = part*10 + (c-'0');
        }
        if(part>255) return -1; //非法格式（单节大于255）
        val = ((val << 8) | part);  //以小端储存
        if(i==3){
            if(c!='\0') //非法格式（过长）
                return -1;
        }else{
            if(c=='\0') //非法格式（提前结束）
                return -1;
        }
    }
    return val;
}

//用于将数字IP地址转化为字符串IP地址
void kern_inet_num2add(char *ip_str , unsigned int ip_num){
    unsigned char *p = (unsigned char*)(&ip_num);
    sprintf(ip_str, "%u.%u.%u.%u", p[0],p[1],p[2],p[3]);
} 

static int __init lkm_init(void)  {  
    nf_register_net_hook(&init_net, &nfho);     //hook函数
    nl_sk = netlink_kernel_create(&init_net, NETLINK_TEST, &cfg);   //netlink处理函数
    if(!nl_sk){
        printk(KERN_ERR"Failed to create netlink!\n");
    }
    printk("Kernel mod registered, start.\n");
    return 0;  
}

static void __exit lkm_exit(void){  
    nf_unregister_net_hook(&init_net, &nfho);   //删除hook函数
    netlink_kernel_release(nl_sk);              //删除netlink处理函数
    printk("Kernel mod unregistered, exit.\n");
}  

module_init(lkm_init);  
module_exit(lkm_exit); 