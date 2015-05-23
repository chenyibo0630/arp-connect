#include <stdio.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <net/if.h>
#include "arp.h"

struct arp_pkg {
	struct ether_header eh;
    struct ether_arp ea;
    u_char padding[18];
};	

void sendArp(u_char *mac,char* source_ip,char *target_ip){
	//create socket
	int req_fd = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ARP));
	if(req_fd < 0){
		printf("create socket error");
		exit(1);
	}
	//init socket address
	struct sockaddr_ll req_head;
	bzero(&req_head,sizeof(req_head));
	req_head.sll_family = PF_PACKET;
	req_head.sll_ifindex = if_nametoindex("eth0");
	//init request data
	struct arp_pkg req_data;
	bzero(&req_data,sizeof(req_data));
	//fill ethernet head
	memcpy(req_data.eh.ether_dhost,(u_char *) "\xff\xff\xff\xff\xff\xff",ETH_ALEN);//6 byte des mac
	memcpy(req_data.eh.ether_shost,mac,ETH_ALEN);//6 byte src mac
	req_data.eh.ether_type = htons(ETHERTYPE_ARP);//2 byte ethernet type
	//fill arp
	req_data.ea.arp_hrd = htons(ARPHRD_ETHER);//2 byte hardware type
	req_data.ea.arp_pro = htons(ETHERTYPE_IP);//2 byte protocol type
	req_data.ea.arp_hln = ETH_ALEN;//1 byte hardware length
	req_data.ea.arp_pln = 4; //1 byte protocol length
	req_data.ea.arp_op = htons(ARPOP_REQUEST); //2 byte arp operation code,request 1,reply 2
	memcpy(req_data.ea.arp_sha,mac,ETH_ALEN);// 6 byte source mac addr
	inet_aton(source_ip,req_data.ea.arp_spa);//4 byte source ip addr
	bzero(req_data.ea.arp_tha,ETH_ALEN);//6 byte target mac addr
	inet_aton(target_ip,req_data.ea.arp_tpa);//4 byte target mac ip
	//send frame
	if(sendto(req_fd, &req_data, sizeof(req_data), 0, (struct sockaddr *)&req_head, sizeof(req_head)) <= 0) {
	    perror("send arp error");
	    exit(1);
    }
}

void getInfo(u_char *mac,struct in_addr *local_ip){
	int fd = socket(AF_INET,SOCK_DGRAM,0);
	struct ifreq macreq;
	strcpy(macreq.ifr_name , "eth0");
	//get mac addr to *mac
	if(ioctl(fd, SIOCGIFHWADDR, &macreq) != 0){
		printf("get mac addr error");
		exit(0);
	}
	memcpy(mac,macreq.ifr_hwaddr.sa_data,ETH_ALEN);
	//get ip addr
	if(ioctl(fd, SIOCGIFADDR, &macreq) != 0){
		printf("get ip addr error");
		exit(0);
	}
	memcpy(local_ip,&((struct sockaddr_in *)(&macreq.ifr_addr))->sin_addr,4);
}

void receiveArp(char* source_ip){
	int recvfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if(recvfd < 0){
			printf("create socket error");
			exit(1);
	}
	u_char recv_data[60];
	
	while(1){
		bzero(recv_data, sizeof(recv_data));
		//receive frame
		if(recvfrom(recvfd, recv_data, sizeof(recv_data), 0, NULL, 0) <= 0){
 			perror("receive arp error");
    		exit(1);
		}
		//check op code, if not reply continue
		if(ntohs(*(u_short *)(recv_data+20)) !=2 ){
			printf("not reply");
			continue;
		}
		//check sour
		u_long sip_l;
		inet_aton(source_ip,&sip_l);
		if(*(u_long *)(recv_data+28)!=sip_l){
			printf("not %s",source_ip);
			continue;
		}
		u_char *mac = (u_char *)(recv_data+22);
		printf("reply mac:%02x:%02x:%02x:%02x:%02x:%02x\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
	}
}