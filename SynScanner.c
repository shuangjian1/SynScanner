#include<stdio.h> 
#include<string.h> 
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

void * receive_ack( void *ptr );
void process_packet(unsigned char* , int);
unsigned short csum(unsigned short * , int );
char * hostname_to_ip(char * );
int get_local_ip (char *);

#define TCPHDR_SIZE sizeof(struct tcphdr)
#define IPHDR_SIZE	sizeof(struct iphdr)
#define PSD_SIZE	sizeof(struct psdhdr)

//use for checkSum
struct psdhdr   
{
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;
	
	struct tcphdr tcp;
};

struct in_addr dest_ip;

int main(int argc, char *argv[])
{
	//Create a raw socket
	int s = socket (AF_INET, SOCK_RAW ,  htons(ETH_P_IP));
	if(s < 0)
	{
		printf ("Error creating socket. Error number : %d . Error message : %s \n" , errno , strerror(errno));
		exit(0);
	}
	else
	{
		printf("Socket created.\n");
	}
		
	//Datagram to represent the packet
	char datagram[4096];	
	
	//IP header
	struct iphdr *iphdr_temp = (struct iphdr *) datagram;
	
	//TCP header
	struct tcphdr *tcphdr_temp = (struct tcphdr *) (datagram + IPHDR_SIZE);
	
	struct sockaddr_in  dest;
	struct psdhdr psh;
	
	char *target = argv[1];
	
	if(argc < 2)
	{
		printf("Please specify a hostname \n");
		exit(1);
	}
	
	if( inet_addr( target ) != -1)
	{
		dest_ip.s_addr = inet_addr( target );
		printf("Destination IP:%s\n",argv[1]);
	}
	else
	{
		char *ip = hostname_to_ip(target);
		if(ip != NULL)
		{
			printf("%s resolved to %s \n" , target , ip);
			//Convert domain name to IP
			dest_ip.s_addr = inet_addr( hostname_to_ip(target) );
		}
		else
		{
			printf("Unable to resolve hostname : %s" , target);
			exit(1);
		}
	}
	
	int source_port = 43591;
	char source_ip[20];
	get_local_ip( source_ip );
	
	printf("Local source IP is %s \n" , source_ip);
	
	memset (datagram, 0, 4096);	/* zero out the buffer */
	
	//Fill in the IP Header
	iphdr_temp->ihl = 5;
	iphdr_temp->version = 4;
	iphdr_temp->tos = 0;
	iphdr_temp->tot_len = IPHDR_SIZE + TCPHDR_SIZE;
	iphdr_temp->id = htons (54321);	//Id of this packet
	iphdr_temp->frag_off = htons(16384);
	iphdr_temp->ttl = 64;
	iphdr_temp->protocol = IPPROTO_TCP;
	iphdr_temp->check = 0;		//Set to 0 before calculating checksum
	iphdr_temp->saddr = inet_addr ( source_ip );	//Spoof the source ip address
	iphdr_temp->daddr = dest_ip.s_addr;
	
	iphdr_temp->check = csum ((unsigned short *) datagram, iphdr_temp->tot_len >> 1);
	
	//TCP Header
	tcphdr_temp->source = htons ( source_port );
	tcphdr_temp->dest = htons (80);
	tcphdr_temp->seq = htonl(1105024978);
	tcphdr_temp->ack_seq = 0;
	tcphdr_temp->doff = TCPHDR_SIZE / 4;		//Size of tcp header
	tcphdr_temp->fin=0;
	tcphdr_temp->syn=1;
	tcphdr_temp->rst=0;
	tcphdr_temp->psh=0;
	tcphdr_temp->ack=0;
	tcphdr_temp->urg=0;
	tcphdr_temp->window = htons ( 14600 );	// maximum allowed window size
	tcphdr_temp->check = 0; //if you set a checksum to zero, your kernel's IP stack should fill in the correct checksum during transmission
	tcphdr_temp->urg_ptr = 0;
	
	//IP_HDRINCL to tell the kernel that headers are included in the packet
	int one = 1;
	const int *val = &one;
	
	if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
	{
		printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
		exit(0);
	}
	
	printf("Starting sniffer thread...\n");
	char *message1 = "Thread 1";
	pthread_t sniffer_thread;

	if( pthread_create( &sniffer_thread , NULL ,  receive_ack , (void*) message1) < 0)
	{
		printf ("Could not create sniffer thread. Error number : %d . Error message : %s \n" , errno , strerror(errno));
		exit(0);
	}

	printf("Starting to send syn packets\n");
	
	int port;
	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = dest_ip.s_addr;
	for(port = 1 ; port < 100 ; port++)
	{
		tcphdr_temp->dest = htons ( port );
		tcphdr_temp->check = 0;	// if you set a checksum to zero, your kernel's IP stack should fill in the correct checksum during transmission
		
		psh.source_address = inet_addr( source_ip );
		psh.dest_address = dest.sin_addr.s_addr;
		psh.placeholder = 0;
		psh.protocol = IPPROTO_TCP;
		psh.tcp_length = htons( TCPHDR_SIZE );
		
		memcpy(&psh.tcp , tcphdr_temp , TCPHDR_SIZE);
		
		tcphdr_temp->check = csum( (unsigned short*) &psh , PSD_SIZE);
		
		//Send the packet
		if ( sendto (s, datagram , IPHDR_SIZE + TCPHDR_SIZE , 0 , (struct sockaddr *) &dest, sizeof (dest)) < 0)
		{
			printf ("Error sending syn packet. Error number : %d . Error message : %s \n" , errno , strerror(errno));
			exit(0);
		}
	}
	pthread_join( sniffer_thread , NULL);
	printf("\nfinish all\n");
	
	return 0;
}

/*
	Method to sniff incoming packets and look for Ack replies
*/
void * receive_ack( void *ptr )
{
	//Start the sniffer thing
	start_sniffer();
}

int start_sniffer()
{
	int sock_raw;
	int i;
	int saddr_size , data_size;
	struct sockaddr saddr;	
	
	unsigned char *buffer = (unsigned char *)malloc(65536); //Its Big!
	
	printf("Sniffer initialising...\n");
	fflush(stdout);
	
	//Create a raw socket that shall sniff
	sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
	
	if(sock_raw < 0)
	{
		printf("Socket Error\n");
		fflush(stdout);
		return 1;
	}
	
	saddr_size = sizeof(saddr);
	printf("Receive packet\n");
	
	for(i=0;i<100;i++)
	{
		//Receive a packet
		data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , &saddr_size);
		printf(".");
		if(data_size <0 )
		{
			printf("Recvfrom error , failed to get packets\n");
			fflush(stdout);
			return 1;
		}
		
		//Now process the packet
		process_packet(buffer , data_size);
		fflush(stdout);
	}
	
	close(sock_raw);
	printf("\nSniffer finished.");
	fflush(stdout);
	return 0;
}

void process_packet(unsigned char* buffer, int size)
{
	//Get the IP Header part of this packet
	struct iphdr *iphdr_temp = (struct iphdr*)buffer;
	struct sockaddr_in source,dest;
	unsigned short iphdr_len;
	if(iphdr_temp->protocol == 6)
	{
		struct iphdr *iphdr_temp = (struct iphdr *)buffer;
		iphdr_len = iphdr_temp->ihl*4;
	
		struct tcphdr *tcphdr_temp=(struct tcphdr*)(buffer + iphdr_len);
			
		memset(&source, 0, sizeof(source));
		source.sin_addr.s_addr = iphdr_temp->saddr;
	
		memset(&dest, 0, sizeof(dest));
		dest.sin_addr.s_addr = iphdr_temp->daddr;
		
		if(tcphdr_temp->syn == 1 && tcphdr_temp->ack == 1 && source.sin_addr.s_addr == dest_ip.s_addr )
		{
			printf("Port %d open" , ntohs(tcphdr_temp->source));
		}
	}
	
}

/*
 Checksums - IP and TCP
 */
unsigned short csum(unsigned short *ptr,int nbytes) 
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;
	
	return(answer);
}

/*
	Get ip from domain name
 */
char* hostname_to_ip(char * hostname)
{
	struct hostent *he;
	struct in_addr **addr_list;
	int i;
		
	if ( (he = gethostbyname( hostname ) ) == NULL) 
	{
		// get the host info
		herror("gethostbyname");
		return NULL;
	}

	addr_list = (struct in_addr **) he->h_addr_list;
	
	for(i = 0; addr_list[i] != NULL; i++) 
	{
		//Return the first one;
		return inet_ntoa(*addr_list[i]) ;
	}
	
	
	return NULL;
}

/*
 Get source IP of system , like 192.168.0.6 or 192.168.1.2
 */

int get_local_ip ( char * buffer)
{
	int sock = socket ( AF_INET, SOCK_DGRAM, 0);

	const char* kGoogleDnsIp = "8.8.8.8";
	int dns_port = 53;

	struct sockaddr_in serv;

	memset( &serv, 0, sizeof(serv) );
	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = inet_addr(kGoogleDnsIp);
	serv.sin_port = htons( dns_port );

	int err = connect( sock , (const struct sockaddr*) &serv , sizeof(serv) );

	struct sockaddr_in name;
	socklen_t namelen = sizeof(name);
	err = getsockname(sock, (struct sockaddr*) &name, &namelen);

	const char *p = inet_ntop(AF_INET, &name.sin_addr, buffer, 100);

	close(sock);
	
}
