#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
 
#define NETLINK_TEST 17
#define MAX_PAYLOAD 1024
#define MAX_RECEIVE_CNT 10              //设置接收上限

int n = MAX_RECEIVE_CNT;
int sock_fd, store_file;
struct iovec iov;
struct msghdr msg;                      //存储发送的信息
struct nlmsghdr *nlh = NULL;            //用于封装信息的头部
struct sockaddr_nl src_addr, dest_addr; //用户pid和kernel的pid（0）

int main(int argc, char *argv[])
{
    sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_TEST);
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();             //本进程pid
    src_addr.nl_groups = 0;
    bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));
 
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;                   //kernel的pid
    dest_addr.nl_groups = 0;
     
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);  //设置缓存空间
    nlh->nlmsg_pid = getpid();                  //本进程pid
    nlh->nlmsg_flags = 0;

    if(argc != 2){
        printf("Missing parameter!\n");
        exit(1);
    }
    strcpy(NLMSG_DATA(nlh), argv[1]);   //从cmd获得要监听的ip地址
 
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
 
    sendmsg(sock_fd, &msg, 0);  //向kernel发信息
 
    //接受返回的routing信息
    //清空缓存
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    store_file = open("./RoutingINFO", O_CREAT|O_WRONLY, 0666);
    while(n--){
        int msgLen = recvmsg(sock_fd, &msg, 0);
        printf("Received mesage: %s\n", (char *)NLMSG_DATA(nlh));
        int ret = write(store_file, (char *)NLMSG_DATA(nlh), strlen((char *)NLMSG_DATA(nlh)));
        if(ret < 0){
            printf("write error.");
            return -1;
        }
        ret = write(store_file, "\n", 1);
        if(ret < 0){
            printf("write error.");
            return -1;
        }
    }
    close(store_file);
    close(sock_fd);
    return 0;
}