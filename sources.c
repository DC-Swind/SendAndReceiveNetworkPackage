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

int start_receive(){
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
        //加快运行速度，使用GOTO语句
        switch((p[12]<<8)+p[13]){
            case 0x0600: printf("XEROX NS IDP \n"); goto End; break;
            case 0x0660:case 0x0661 printf("DLOG \n"); goto End; break;
            case 0x0800: printf("IP Header: \n"); goto Net_IP; break;
            case 0x0801: printf("X.75 Internet \n"); goto End; break;
            case 0x0802: printf("NBS Internet \n"); goto End; break;
            case 0x0803: printf("ECMA Internet \n"); goto End; break;
            case 0x0804: printf("Chaosnet \n"); goto End; break;
            case 0x0805: printf("X.25 Level 3 \n"); goto End; break;
            case 0x0806: printf("ARP- Address Resolution Protocol \n"); goto End; break;
            case 0x0808: printf("ARP- Frame Relay ARP[RFC1701] \n"); goto End; break;
            case 0x8035: printf("RARP \n"); goto Net_RARP; break;
            case 0x8037: printf("Novell Netware IPX \n"); goto Net_RARP; break;
            case 0x809B: printf("EtherTalk \n"); goto Net_RARP; break;
            case 0x80D5: printf("IBM SNA Services over Ethernet \n"); goto Net_RARP; break;
            case 0x80F3: printf("AppleTalk Address Resolution Protocol \n"); goto Net_RARP; break;
            case 0x8100: printf("Ethernet Automatic Protection Switching \n"); goto Net_RARP; break;
            case 0x8137: printf("Internet Packet Exchange \n"); goto Net_RARP; break;
            case 0x814C: printf("Simple Network Management Protocol \n"); goto Net_RARP; break;
            case 0x86DD: printf("Internet Protocol version 6 \n"); goto Net_RARP; break;
            case 0x880B: printf("Point-to-Point Protocol \n"); goto Net_RARP; break;
            case 0x880C: printf("General Switch Management Protocol \n"); goto Net_RARP; break;
            case 0x8847: printf("Multi-Protocol Label Switching <unicast> \n"); goto Net_RARP; break;
            case 0x8848: printf("Multi-Protocol Label Switching <multicast> \n"); goto Net_RARP; break;
            case 0x8863: printf("PPP Over Ethernet <Discovery Stage> \n"); goto Net_RARP; break;
            case 0x8864: printf("PPP Over Ethernet<PPP Session Stage> \n"); goto Net_RARP; break;
            case 0x88BB: printf("Light Weight Access Point Protocol \n"); goto Net_RARP; break;
            case 0x88CC: printf("Link Layer Discovery Protocol \n"); goto Net_RARP; break;
            case 0x8E88: printf("EAP over LAN \n"); goto Net_RARP; break;
            case 0x9000: printf("Loopback \n"); goto Net_RARP; break;
            case 0x9100: case 0x9200: printf("VLAN Tag Protocol Identifier \n"); goto Net_RARP; break;
            default: printf("do not support\n");;
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
            case IPPROTO_ICMP:printf("icmp\n");
                
                break;
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
int main(int argc,char* argv[]){
    //before receive, send a icmp package
    init_send();
    //------------------------------
    start_receive();
    return -1;
}
