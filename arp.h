void getInfo(u_char *mac,struct in_addr *local_ip);
void sendArp(u_char *mac,char* source_ip,char *target_ip);
void receiveArp(char* source_ip);