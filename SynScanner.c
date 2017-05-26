/*************************************************************************
    > File Name: SynScanner.c
    > Author: yh
    > Mail: yanghuancoder@163.com 
    > Created Time: Thu 25 May 2017 11:41:47 PM CST
 ************************************************************************/

#include<stdio.h>
#include<assert.h>
#include<stdlib.h>
#include<unistd.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<netinet/in.h>
#include<string.h>
#include<arpa/inet.h>
#include<pthread.h>
#include<sys/socket.h>
#include<ctype.h>
#include<netdb.h>


typedef struct psd_hdr{
	uint32_t saddr;
	uint32_t daddr;	
	uint8_t mbz;		
	uint8_t protocol;			
	uint16_t tcp_length;	

	struct tcphdr tcp;
}PSD_HEADER;

#define TCP_HEADER_SIZE sizeof(struct tcphdr)
#define PSD_HEADER_SIZE sizeof(PSD_HEADER)
#define IP_HEADER_SIZE	sizeof(struct iphdr)

#define PACKAGE_SIZE 1024
#define MIN_TCP_HEADER_SIZE 20
#define MIN_PSD_HEADER_SIZE 12 

#define SRC_ADDR "192.168.78.130"
#define SRC_PORT 65531

#define DEST_ADDR "192.168.2.1"

void sendSyn(uint16_t port, int flags);
void *recvSynThread();
unsigned short checkSum(unsigned short *ptr,int nbytes);

struct sockaddr_in dest_addr;
struct sockaddr_in src_addr;
static int fd;

int main(int argc, char *argv[]){

	//printf("%d %d\n", TCP_HEADER_SIZE, PSD_HEADER_SIZE);

	if(argc > 1){
		if(argv[1][0] >= '0' && argv[1][0] <='9'){
			//is digit addr like 192.168.78.1
			src_addr.sin_addr.s_addr = inet_addr(argv[1]);
		}else{
			//is a dns name
			struct hostent *temp;
			if((temp = gethostbyname(argv[1])) == NULL){
				herror("get host fails:");
				exit(0);
			}
			struct in_addr **list = (struct in_addr **)temp->h_addr_list;
			src_addr.sin_addr.s_addr = inet_addr(inet_ntoa(*list[0]));
		}
	}else{
		assert(1);	
	}
	dest_addr.sin_addr.s_addr = inet_addr(DEST_ADDR);
	src_addr.sin_family = AF_INET;
	dest_addr.sin_family = AF_INET;

	fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if(fd == -1){
		perror("create socket fails:");
		exit(0);
	}

	pthread_t tid;
	if(pthread_create(&tid, NULL, recvSynThread, NULL) == -1){
		perror("create thread fails:");
		exit(0);
	}

	int port = 0;
	for(; port < 1024; ++port){
		sendSyn(port, 2);
	}
	pthread_join(tid, NULL);

	return 0;
}

void sendSyn(uint16_t port, int flags){

	struct tcphdr *tcphd;
	PSD_HEADER psdhd;
	struct iphdr *iphd;

	char buf[PACKAGE_SIZE] = {
		0
	};

	iphd = (struct iphdr *) buf;
	tcphd = (struct tcphdr *) (buf + IP_HEADER_SIZE);
	//initial iphdr
	iphd->ihl = 5;
	iphd->version = 4;
	iphd->tos = 0;
	iphd->tot_len = TCP_HEADER_SIZE + IP_HEADER_SIZE;
	iphd->id = htons(23333);
	iphd->frag_off = htons(16384);
	iphd->ttl = 64;
	iphd->protocol = IPPROTO_TCP;
	iphd->check = 0;
	iphd->daddr = dest_addr.sin_addr.s_addr;
	iphd->saddr = src_addr.sin_addr.s_addr;
	iphd->check = checkSum((uint16_t *) buf, iphd->tot_len >> 1);
	//initial tcphdr
	tcphd->source = htons(SRC_PORT);
	tcphd->dest = htons(port);
	tcphd->seq = htonl(12345678);
	tcphd->ack_seq = 0;
	tcphd->doff = TCP_HEADER_SIZE / 4;
	tcphd->th_flags = flags;
	tcphd->check = 0;
	tcphd->window = htons(2333);
	tcphd->urg_ptr = 0;

	psdhd.saddr = inet_addr(SRC_ADDR);
	psdhd.daddr = dest_addr.sin_addr.s_addr;
	psdhd.mbz = 0;
	psdhd.protocol = IPPROTO_TCP;
	psdhd.tcp_length = htons(TCP_HEADER_SIZE);
	memcpy(&psdhd.tcp, tcphd, TCP_HEADER_SIZE);
	tcphd->check = checkSum((uint16_t *)&psdhd, PSD_HEADER_SIZE);


	int ret = sendto(fd, buf, IP_HEADER_SIZE + TCP_HEADER_SIZE,
			0, (struct sockaddr *) &dest_addr, sizeof(dest_addr));
	if(ret < 0){
		perror("send syn fails:");
		exit(0);
	}
}

void *recvSynThread(){
	char buf[65536];
	struct sockaddr s_addr;
	socklen_t len = sizeof(s_addr);
	printf("receive package\n");
	while(1){
		memset(buf, 0, sizeof(buf));
		int data_size = recvfrom(fd, buf, sizeof(buf), 0,
				&s_addr, &len);
		if(data_size < 0){
			perror("recvfrom fails");
			exit(0);
		}
		printf(".");
		struct iphdr *ip = (struct iphdr *)buf;
		struct tcphdr *tcp = (struct tcphdr *)(buf + IP_HEADER_SIZE);
		if(ip->saddr == dest_addr.sin_addr.s_addr){
			if(tcp->syn == 1 && tcp->ack == 1){
				printf("port %d is open\n", ntohs(tcp->source));
				sendSyn(ntohs(tcp->source), 4);
			}else{ 
				printf("port %d is close\n", ntohs(tcp->source));
			}
		}
	}

	return NULL;
}

unsigned short checkSum(unsigned short *ptr,int nbytes) 
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
	return (answer);
}	
