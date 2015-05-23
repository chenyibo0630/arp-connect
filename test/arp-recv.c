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

void receiveArp(char* source_ip);

void main(int argc,char **argv){
	if(argc!=2){
		printf("arg number must be 1!\n");
		exit(0);
	}
    receiveArp(argv[1]);

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