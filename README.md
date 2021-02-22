## 一个Linux lkm + app programm

lkm部分用c编写，采用netfilter的钩子函数监控 `hooknum = NF_INET_LOCAL_OUT` （即从本机发送的数据包），向用户程序返回指定源ip的五元组，并且输出相应信息到日志。由于对golang很不熟悉（只做过之前提到的图书管理系统，并且实现的都是简单的基础逻辑），所以尝试用golang编写app programm失败，app programm也采用c语言完成。主要功能即从命令行获取监听的ip地址，再采用netlink与kernel通信将该地址传送给kernel，并且接收kernel返回的五元组信息，将其储存在RoundINFO文件中。

#### LKM部分实现

lkm部分实现了下述方法，具体实现细节在代码中进行了相应的注释。为保证稳定性，netlink_to_uesr函数采取非阻塞式发送，避免由于缓冲区满而导致内核产生忙等。

~~~C
//函数声明
unsigned int kern_inet_add2num(char *ip_str);	//将地址转换为数字
void kern_inet_num2add(char *ip_str , unsigned int ip_num);	//将数字转换为地址
unsigned int getRoutingInfo(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);	//获取五元组
static void nl_data_ready(struct sk_buff *skb);	//从client获取ip
int netlink_to_user(char *msg, int len);	//将信息发送给client

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
~~~

#### Client部分实现

user.c程序是这里的client，实现了单一功能：从命令行读取ip地址发送给kernel并将kernel返的五元组存在RoutingINFO文件中。所有功能全部放在main函数中，这里设置最多接收的消息数量为10条（）：

~~~C
 
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
    src_addr.nl_groups = 0;                 //不加入多播组
    bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));
 
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;                   //kernel的pid
    dest_addr.nl_groups = 0;                //不加入多播组
     
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);  //设置缓存空间
    nlh->nlmsg_pid = getpid();
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
~~~

#### 程序运行

通Makefile来运行，运行 `make Routing` 即可获得输出结果

~~~MakeFF
obj-m += GetRouting.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

Routing:
	make
	-sudo rmmod GetRouting
	sudo dmesg -C
	sudo insmod GetRouting.ko
	dmesg
	gcc user.c -o user
	# IP address to listen. 
	./user 192.168.17.131
	dmesg
~~~
