#include<stdio.h> 
#include<string.h> 
#include<unistd.h>
#include<stdlib.h> 
#include<sys/socket.h>
#include<errno.h> 
#include<pthread.h>
#include<netdb.h>	
#include<arpa/inet.h>
#include<netinet/tcp.h>	
#include<netinet/ip.h>	
#include<netinet/ether.h> 
#include<time.h>

//use for checkSum
struct psdhdr   
{
	uint32_t source_address;
	uint32_t dest_address;
	uint8_t placeholder;
	uint8_t protocol;
	uint16_t tcp_length;
	struct tcphdr tcp;
};

void *receivePackage();
void checkSynReport(uint8_t* , int);
uint16_t checkSum(uint16_t * , int );
char *getHostByName(char * );
void InitialIpHdr(struct iphdr *iphdr_temp, char *datagram);
void InitialTcpHdr(struct tcphdr *tcphdr_temp, char *datagram);
void InitialPSDhdr(struct psdhdr *psh);
void InitialDestIp(char *target);
void sendPackageToDest(int port, int flags);
int getHostNetIp (char *);


#define TCPHDR_SIZE sizeof(struct tcphdr)
#define IPHDR_SIZE	sizeof(struct iphdr)
#define PSD_SIZE	sizeof(struct psdhdr)


struct in_addr dest_ip;
struct iphdr *iphdr_temp;
struct psdhdr psh;
int s;
struct tcphdr *tcphdr_temp;
int source_port = 43591;
char source_ip[20];
//Datagram to represent the packet
char datagram[4096];	

int main(int argc, char *argv[])
{
	
	
	if(argc < 2){
		printf("Please specify a hostname \n");
		exit(1);
	}

	//Create a raw socket
	s = socket (AF_INET, SOCK_RAW ,  htons(ETH_P_IP));
	if(s < 0){
		perror("create socket fails");
		exit(0);
	}
	
	
	//IP header
	iphdr_temp = (struct iphdr *) datagram;
	
	//TCP header
	tcphdr_temp = (struct tcphdr *) (datagram + IPHDR_SIZE);
	
	//fill the dest ip 
	InitialDestIp(argv[1]);
	//get this host's ip
	getHostNetIp(source_ip);
	
	printf("LocalHost Ip address is %s \n" , source_ip);
	//initial the buffer
	memset (datagram, 0, 4096);	
	
	//fill in the IP Header
	InitialIpHdr(iphdr_temp, datagram);
	
	//fill in the TCP Header
	InitialTcpHdr(tcphdr_temp, datagram);
	//fill in the PSD hdr
	InitialPSDhdr(&psh);

	//IP_HDRINCL to tell the kernel that headers are included in the packet
	int one = 1;
	const int *val = &one;
	if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0){
		perror("setting IP_HDRINCL fails:");
		exit(0);
	}
	
	//create thread to recive the package to scanner port
	pthread_t tid;
	if( pthread_create(&tid, NULL, receivePackage, NULL) < 0){
		perror("Create Thread fails:");
		exit(0);
	}
	
	int port;
	for(port = 1; port < 1024; port++){
		sendPackageToDest(port, 0x2);
	}
	pthread_join(tid, NULL);
	printf("\nfinish all\n");
	
	return 0;
}

void InitialDestIp(char *target){
	if( inet_addr(target) != -1){
		dest_ip.s_addr = inet_addr(target);
		printf("Dest IP:%s\n",target);
	}
	else{
		char *ip = getHostByName(target);
		if(ip != NULL){
			printf("%s find IP is %s \n" , target , ip);
			//Convert domain name to IP
			dest_ip.s_addr = inet_addr(getHostByName(target));
		}
		else{
			perror("find host fails:");
			exit(1);
		}
	}
}

void InitialPSDhdr(struct psdhdr *psh){
	psh->source_address = inet_addr(source_ip);
	psh->dest_address = dest_ip.s_addr;
	psh->placeholder = 0;
	psh->protocol = IPPROTO_TCP;
	psh->tcp_length = htons(TCPHDR_SIZE);
}

//fill in the IP Header
void InitialIpHdr(struct iphdr* iphdr_temp, char *datagram){
	
	iphdr_temp->ihl = 5;
	iphdr_temp->version = 4;
	iphdr_temp->tos = 0;
	iphdr_temp->tot_len = IPHDR_SIZE + TCPHDR_SIZE;
	iphdr_temp->id = htons (54321);	//Id of this packet
	iphdr_temp->frag_off = htons(16384);
	iphdr_temp->ttl = 64;
	iphdr_temp->protocol = IPPROTO_TCP;
	iphdr_temp->check = 0;		//Set to 0 before calculating checksum
	iphdr_temp->saddr = inet_addr (source_ip);	//Spoof the source ip address
	iphdr_temp->daddr = dest_ip.s_addr;
	
	iphdr_temp->check = checkSum ((uint16_t *) datagram, iphdr_temp->tot_len >> 1);
}

//fill TCP Header
void InitialTcpHdr(struct tcphdr *tcphdr_temp, char *datagram){
	tcphdr_temp->source = htons (source_port);
	tcphdr_temp->dest = htons (80);
	tcphdr_temp->seq = htonl(1105024978);
	tcphdr_temp->ack_seq = 0;
	tcphdr_temp->doff = TCPHDR_SIZE / 4;		//Size of tcp header
	tcphdr_temp->window = htons (14600);	// maximum allowed window size
	tcphdr_temp->check = 0; //if you set a checksum to zero, your kernel's IP stack should fill in the correct checksum during transmission
	tcphdr_temp->urg_ptr = 0;
}


void sendPackageToDest(int port, int flags){
	tcphdr_temp->dest = htons (port);
	tcphdr_temp->check = 0;	// if you set a checksum to zero, your kernel's IP stack should fill in the correct checksum during transmission
	tcphdr_temp->th_flags = flags;	
	
	memcpy(&psh.tcp, tcphdr_temp, TCPHDR_SIZE);
	//fill the checkSum
	tcphdr_temp->check = checkSum((uint16_t*) &psh, PSD_SIZE);
	
	struct sockaddr_in dest;

	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = dest_ip.s_addr; 

		//Send the packet
	if (sendto(s, datagram, IPHDR_SIZE + TCPHDR_SIZE, 0, (struct sockaddr *) &dest, sizeof (dest)) < 0){
		herror("send package fails:");
		exit(0);
	}
}

//get package
void * receivePackage(){
	int sock_raw;
	int i;
	int saddr_size, data_size;
	struct sockaddr saddr;	
	
	uint8_t *buffer = (uint8_t *)malloc(65536); 
	
	//Create a raw socket that shall sniff
	sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	
	if(sock_raw < 0){
		perror("sock create fails:");
		exit(0);
	}
	
	saddr_size = sizeof(saddr);
	printf("Receive packet\n");
	
	for(i=0; i<500; i++){
		//Receive a packet
		data_size = recvfrom(sock_raw, buffer, 65536, 0, &saddr, &saddr_size);
		printf(".");
		if(data_size <0 ){
			perror("receive package fails:");
			exit(0);
		}
		
		//Now process the packet
		checkSynReport(buffer, data_size);
		fflush(stdout);
	}
	
	close(sock_raw);
	printf("\nSniffer finished.");
	fflush(stdout);
}

void checkSynReport(uint8_t* buffer, int size){
	//Get the IP Header part of this packet
	struct iphdr *iphdr_temp = (struct iphdr*)buffer;
	struct sockaddr_in source,dest;
	uint16_t iphdr_len;
	if(iphdr_temp->protocol == 6){
		struct iphdr *iphdr_temp = (struct iphdr *)buffer;
		iphdr_len = iphdr_temp->ihl*4;
	
		struct tcphdr *tcphdr_temp=(struct tcphdr*)(buffer + iphdr_len);
			
		memset(&source, 0, sizeof(source));
		source.sin_addr.s_addr = iphdr_temp->saddr;
	
		memset(&dest, 0, sizeof(dest));
		dest.sin_addr.s_addr = iphdr_temp->daddr;
		
		if(tcphdr_temp->syn == 1 && tcphdr_temp->ack == 1 
			&& source.sin_addr.s_addr == dest_ip.s_addr ){
			int port = ntohs(tcphdr_temp->source);
			printf("\nPort %d open\n", port);
			//send rst package to finish the service client's wait
			sendPackageToDest(port, 0x4);
		}
	}
	
}

/*
 Checksums - IP and TCP
 */
uint16_t checkSum(uint16_t *ptr, int nbytes) {
	register long sum;
	uint16_t oddbyte;
	register short answer;

	sum = 0;
	while(nbytes > 1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes == 1) {
		oddbyte = 0;
		*((u_char*)&oddbyte) = *(u_char*)ptr;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;
	
	return(answer);
}

/*
	Get ip from domain name
 */
char* getHostByName(char * hostname){
	struct hostent *he;
	struct in_addr **addr_list;
	int i;
		
	if ((he = gethostbyname(hostname)) == NULL) {
		// get the host info
		herror("gethostbyname");
		return NULL;
	}

	addr_list = (struct in_addr **) he->h_addr_list;
	
	for(i = 0; addr_list[i] != NULL; i++) {
		//Return the first one;
		return inet_ntoa(*addr_list[i]) ;
	}
	
	
	return NULL;
}

/*
 Get source IP of system , like 192.168.0.6 or 192.168.1.2
 */

int getHostNetIp (char * buffer){
	int sock = socket (AF_INET, SOCK_DGRAM, 0);

	const char* kGoogleDnsIp = "8.8.8.8";
	int dns_port = 53;

	struct sockaddr_in serv;

	memset(&serv, 0, sizeof(serv));
	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = inet_addr(kGoogleDnsIp);
	serv.sin_port = htons(dns_port);

	int err = connect(sock , (const struct sockaddr*) &serv, sizeof(serv));

	struct sockaddr_in name;
	socklen_t namelen = sizeof(name);
	err = getsockname(sock, (struct sockaddr*)&name, &namelen);

	const char *p = inet_ntop(AF_INET, &name.sin_addr, buffer, 100);

	close(sock);
	
}
