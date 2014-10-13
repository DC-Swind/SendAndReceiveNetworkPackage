#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#define BUFFER_MAX 2048

int init_send(){
    int sendsd = socket(AF_INET,SOCK_RAW,htons(ETH_P_ALL));
    if (sendsd < 0){
        printf("create send raw socket error! ");
        return 0;
    }else printf("create send raw socket successfully\n");

    //创建IP头和ICMP头
    struct iphdr* ip;
    struct icmphdr* icmp;
    struct sockaddr_in connection;
    char packet[sizeof(struct iphdr) + sizeof(struct icmphdr)];

    ip = (struct iphdr*) packet;
    icmp = (struct icmphdr*) (packet + sizeof(struct iphdr));
 
    //IP
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr);
    ip->id = 0;
    ip->ttl = 63;
    ip->protocol = IPPROTO_ICMP;
    ip->saddr = inet_addr("192.168.0.2");  //source ip
    ip->daddr = inet_addr("192.168.1.2");  //dest ip
 
    //ICMP
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = 0;
    icmp->un.echo.sequence = 0;
    icmp->checksum = 0;
 
    //目标IP
    connection.sin_family = AF_INET;
    connection.sin_addr.s_addr = inet_addr("192.168.1.2");
 
    //Sendto
    int nn;
    if((nn = sendto(sendsd, packet, ip->tot_len, 0,(struct sockaddr *)&connection, sizeof(struct sockaddr))) < 0){
        printf("sendto error");
        exit(-1);
    }else{
        printf("send %d OK\n",nn);
    }
}

int main(int argc,char* argv[]){
    //before receive, send a icmp package
    init_send();
    //------------------------------
    int sock_fd;
    int proto;
    int n_read;
    char buffer[BUFFER_MAX];
    char *eth_head;
    char *ip_head;
    char *tcp_head;
    char *udp_head;
    char *icmp_head;
    unsigned char *p;
    if((sock_fd=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL)))<0){
        printf("error create raw socket\n");
        return -1;
    }
    while(1){
        n_read = recvfrom(sock_fd,buffer,2048,0,NULL,NULL);
        if(n_read < 42){
            printf("error when recv msg \n");
            return -1;
        }
        eth_head = buffer;
        p = eth_head;
        printf("-------------------Start Of A Package---------------------\n");
        printf("MAC address: %.2x:%02x:%02x:%02x:%02x:%02x==> %.2x:%02x:%02x:%02x:%02x:%02x\n",p[6],p[7],p[8],p[9],p[10],p[11],p[0],p[1],p[2],p[3],p[4],p[5]);
        //减小时间复杂度，使用GOTO语句
        switch(p[12]<<8+p[13]){
            case 0x0800: printf("IP Header: \n"); goto Net_IP; break;
            case 0x8035: printf("RARP: \n"); goto Net_RARP; break;
            default: ;
        }
        
    Net_IP:;
        ip_head = eth_head+14;
        struct iphdr* ip = ip_head;
        printf("--version: %d \n--service type: %d \n--fragment offset: %d \n--protocol: %d \n",ip->version,ip->tos,ip->frag_off,ip->protocol);
        p = ip_head+12;
        printf("--IP:%d.%d.%d.%d==> %d.%d.%d.%d\n",p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7]);
        
        proto = (ip_head + 9)[0];
        struct icmphdr* icmp = ip_head +20;
        printf("Protocol:");
        switch(proto){
            case IPPROTO_ICMP:printf("icmp\n");break;
            case IPPROTO_IGMP:printf("igmp\n");break;
            case IPPROTO_IPIP:printf("ipip\n");break;
            case IPPROTO_TCP: printf("tcp\n"); break;
            case IPPROTO_UDP: printf("udp\n"); break;
            default:printf("Pls query yourself\n");
        }
        goto End;
    Net_RARP:;
        goto End;
        
    End:;
    }
    return -1;
}
