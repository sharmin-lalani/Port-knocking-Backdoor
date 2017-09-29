/*
This is a Port-knocker client that issues the sequence of the packets that will enable the backdoor.
Command execution syntax: knocker <path-to-config-file> <IPaddress>

The configuration file will contain the port sequence (one per line) 
and the IP address should be the target IPv4 address that runs the backdoor service.

The primary purpose of port knocking is to prevent an attacker 
from scanning a system for potentially exploitable services by doing a port scan.
Unless the attacker sends the correct knock sequence, the protected ports will appear closed.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h> 

int main(int argv, char** argc) {

	FILE *config_file; 
	int sockfd, n, serverlen;
	short unsigned int port_num;
	struct sockaddr_in serveraddr, srcaddr;

	// parse the config file   	
	config_file = fopen(argc[1],"r");
    	if(config_file == NULL) {
        	printf("Unable to open config file.\n");
		return -1;
    	}

	
    	/* socket: create the socket */
    	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    	if (sockfd < 0) {
        	printf("ERROR opening socket\n");
		return -1;
	}

    	/* build the server's Internet address */
    	memset(&serveraddr, 0, sizeof(serveraddr));
    	serveraddr.sin_family = AF_INET;
	inet_aton(argc[2], &serveraddr.sin_addr);

	/* build the knocker's Internet address */
	memset(&srcaddr, 0, sizeof(srcaddr));
	srcaddr.sin_family = AF_INET;
	srcaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    	srcaddr.sin_port = htons(22222);

	/* bind the client socket */
	if (bind(sockfd, (struct sockaddr *) &srcaddr, sizeof(srcaddr)) < 0)
		printf("ERROR in bind\n");

	serverlen = sizeof(serveraddr);

	while (fscanf(config_file, "%hu", &port_num) == 1) {
		//printf("%d\n", port_num);		

		serveraddr.sin_port = htons(port_num);
    		/* send the message to the server */
    		n = sendto(sockfd, NULL, 0, 0, (const sockaddr*)&serveraddr, serverlen);
    		if (n < 0) 
      			printf("ERROR in sendto\n");
		//else
			//printf("packet successfully sent\n");
		sleep(0.1);    

	}
	fclose(config_file);
	return 0;
}
