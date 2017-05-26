/*************************************************************************
    > File Name: SynScanner.c
    > Author: yh
    > Mail: yanghuancoder@163.com 
    > Created Time: Thu 25 May 2017 11:41:47 PM CST
 ************************************************************************/

#include<stdio.h>
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
	unsigned long saddr;
	unsigned long daddr;	
	char mbz;		
	char protocol;			
	unsigned short tcp_length;	
}PSD_HEADER;

int TCP_HEADER_SIZE = sizeof(struct tcphdr);
int PSD_HEADER_SIZE = sizeof(PSD_HEADER);

#define SEND_PACKAGE_SIZE 256
#define RECV_PACKAGE_SIZE 1024
#define MIN_TCP_HEADER_SIZE 20
#define MIN_PSD_HEADER_SIZE 20

#define SRC_ADDR "192.168.78.130"
#define SRC_PORT 23

#define DEST_ADDR "192.168.2.1"

void sendSyn(int port, int flags);
void *recvSynThread();
unsigned short checkSum(unsigned short *ptr,int nbytes);

struct sockaddr_in dest_addr;
struct sockaddr_in src_addr;
static int fd;

int main(int argc, char *argv[]){

	//printf("%d %d\n", TCP_HEADER_SIZE, PSD_HEADER_SIZE);

	if(argc > 1){
		
		char *input_ip = argv[1];

		//fill dest and src socket struct
		dest_addr.sin_family = AF_INET;
		if(input_ip[0] >= '0' && input_ip[0] <= '9'){
			printf("here\n");
			dest_addr.sin_addr.s_addr = inet_addr(input_ip);
			printf("addr : %s\n", inet_ntoa(dest_addr.sin_addr));
		}
		else{
			printf("here\n");
			struct hostent *temp;
			temp = gethostbyname(input_ip);
			dest_addr.sin_addr.s_addr = ((struct in_addr *)temp->h_addr_list)->s_addr;
			printf("addr : %s\n", inet_ntoa(dest_addr.sin_addr));
		}

		src_addr.sin_family = AF_INET;
		src_addr.sin_addr.s_addr = inet_addr("192.168.2.1");

		fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

		if(fd == -1){
			perror("socket create fail");
			exit(0);
		}

		int i = 0;
		pthread_t tid;
		pthread_create(&tid, NULL, recvSynThread, NULL);
		for(; i < 1024; ++i){
			sendSyn(i, 2);			
		}
		pthread_join(tid, NULL);

		close(fd);	
	}else{

		//fill dest and src socket struct
		dest_addr.sin_family = AF_INET;
		dest_addr.sin_addr.s_addr = inet_addr(DEST_ADDR);

		src_addr.sin_family = AF_INET;
		src_addr.sin_addr.s_addr = inet_addr(SRC_ADDR);

		fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

		if(fd == -1){
			perror("socket create fail");
			exit(0);
		}

		int i = 0;
		pthread_t tid;
		pthread_create(&tid, NULL, recvSynThread, NULL);
		for(; i < 1024; ++i){
			sendSyn(i, 2);			
		}
		pthread_join(tid, NULL);

		close(fd);	

	}

	return 0;
}

void sendSyn(int port, int flags){
	dest_addr.sin_port = htons(port);

	char package[SEND_PACKAGE_SIZE] = {0};
	struct tcphdr tcp;
	PSD_HEADER psd;

	//fill tcp
	tcp.th_sport = htons(SRC_PORT);
	tcp.th_dport = htons(port);
	tcp.th_seq = htonl(23333);
	tcp.th_ack = 0;
	tcp.th_off = TCP_HEADER_SIZE/4;
	
	tcp.th_flags = flags;

	tcp.th_win = htons(16384);
	tcp.th_urp = 0;
	tcp.th_sum = 0;
	//fill psd
	psd.saddr = src_addr.sin_addr.s_addr;
	psd.daddr = dest_addr.sin_addr.s_addr;
	psd.mbz = 0;
	psd.protocol = IPPROTO_TCP;
	psd.tcp_length = htons(TCP_HEADER_SIZE);


	memcpy(package, &psd, PSD_HEADER_SIZE);
	memcpy(package+PSD_HEADER_SIZE, &tcp, TCP_HEADER_SIZE);

	tcp.th_sum = checkSum((unsigned short *)package, TCP_HEADER_SIZE+PSD_HEADER_SIZE);

	memcpy(package, &tcp, TCP_HEADER_SIZE);

	int ret = sendto(fd, package, TCP_HEADER_SIZE, 0, 
			(struct sockaddr *)&dest_addr, sizeof(dest_addr));
	if(ret == -1){
		perror("send error:");
		exit(2);
	}
}

void *recvSynThread(){
	struct tcphdr *tcp;
	char package[RECV_PACKAGE_SIZE];
	int length = sizeof(src_addr);
	printf("run\n");
	while(1){
		//wait package
		memset(package, 0, RECV_PACKAGE_SIZE);
		int size = recvfrom(fd, package, RECV_PACKAGE_SIZE, 0, 
				(struct sockaddr *)&src_addr, (socklen_t *)&length);
		if(size == -1){
			perror("recvfrom err:");
			break;
		}
		tcp = (struct tcphdr *)(package + sizeof(struct iphdr));

		if(size < (MIN_PSD_HEADER_SIZE + MIN_TCP_HEADER_SIZE)){
			continue;
		}
		if(ntohs(tcp->th_dport) != SRC_PORT){
			continue;
		}
		if(tcp->syn == 1 && tcp->ack == 1){
			sendSyn(tcp->th_sport, 4);
			printf("port %d is open! because of ACK AND SYN is true", ntohs(tcp->th_sport));
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
