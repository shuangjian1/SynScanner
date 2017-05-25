/*************************************************************************
    > File Name: SynScanner.c
    > Author: yh
    > Mail: yanghuancoder@163.com 
    > Created Time: Thu 25 May 2017 11:41:47 PM CST
 ************************************************************************/

#include<stdio.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<pthread.h>
#include<sys/socket.h>
#include<sys/types.h>

#define SEND_PACKAGE_SIZE 256
#define RECV_PACKAGE_SIZE 1024
#define MIN_TCP_HEADER_SIZE 20
#define MIN_PSD_HEADER_SIZE 20
#define SRC_PORT 65531


typedef struct psd_hdr{
	unsigned long saddr;
	unsigned long daddr;	
	char mbz;		
	char protocol;			
	unsigned short tcp_length;	
}PSD_HEADER;

typedef struct _tcphdr{
	uint16_t src_port;
	uint16_t des_port;
	uint32_t seq;
	uint32_t ack_seq;
	uint16_t header_len : 4;
	uint16_t remain		: 6;
	union{
		uint16_t flag	: 6;
		struct{
			uint16_t URG		: 1;
			uint16_t ACK		: 1;
			uint16_t PSH		: 1;
			uint16_t RST		: 1;
			uint16_t SYN		: 1;
			uint16_t FIN		: 1;
		};
	};
	uint16_t window_size;
	uint16_t check_sum;
	uint16_t urp;
}TCP_HEADER;

#define TCP_HEADER_SIZE sizeof(TCP_HEADER)
#define PSD_HEADER_SIZE sizeof(PSD_HEADER)

void sendSyn(int port);
void *recvSynThread();
uint16_t checkSum(uint16_t *addr, int len);

struct sockaddr_in dest_addr;
struct sockaddr_in src_addr;
static int fd;

int main(int argc, char *argv[]){

	if(argc > 2){
		
		char *input_ip = argv[1];


		//fill dest and src socket struct
		dest_addr.family = AF_INET;
		dest_addr.sin_addr.s_addr = inet_addr(input_ip);

		src_addr.family = AF_INET;
		src_addr.sin_addr.sin_addr = inet_addr("192.168.2.1");

		fd = sokect(AF_INET, SOCK_RAW, IPPROTO_TCP);

		if(fd == -1){
			perror("socket create fail");
			exit(0);
		}

		int i = 0;
		pthread_t tid;
		pthread_create(&tid, NULL, recvSynThread, NULL);
		for(int i = 0; i < 1024; ++i){
			sendSyn(i);			
		}
		pthread_join(tid, NULL);

		close(fd);	
	}else{

	}

	return 0;
}

void sendSyn(int port, int flags){
	dest_addr.sin_port = htons(port);

	char package[SEND_PACKAGE_SIZE] = {0};
	TCP_HEADER tcp;
	PSD_HEADER psd;

	//fill tcp
	tcp.src_port = htons(SRC_PORT);
	tcp.des_port = htons(port);
	tcp.seq = htonl(23333);
	tcp.ack_seq = 0;
	tcp.header_len = TCP_HEADER_SIZE;
	tcp.remain = 0;
	
	tcp.flag = flags;

	tcp.window_size = htons(16384);
	tcp.urp = 0;
	tcp.check_sum = 0;
	//fill psd
	psd.saddr = src_addr.sin_addr.s_addr;
	psd.daddr = dest_addr.sin_addr.s_addr;
	psd.mbz = 0;
	psd.protocol = IPPROTO_TCP;
	psd.tcp_length = htons(TCP_HEADER_SIZE)


	memset(package, &psd, PSD_HEADER_SIZE);
	memset(package+PSD_HEADER_SIZE, &tcp, TCP_HEADER_SIZE);

	tcp.check_sum = checkSum((uint8_t *)package, TCP_HEADER_SIZE+PSD_HEADER_SIZE);

	memcpy(package, &tcp, TCP_HEADER_SIZE);

	int ret = sendto(fd, package, TCP_HEADER_SIZE, 0, 
			(struct sockaddr *)&dest_addr, sizeof(dest_addr));
	if(ret == -1){
		perror("send error:");
		exit(2);
	}else{
		printf("send ok\n");
	}
}
void *recvSynThread(){
	TCP_HEADER tcp;
	char package[RECV_PACKAGE_SIZE];
	int length = sizeof(src_addr);
	while(1){
		//wait package
		memset(package, 0, RECV_PACKAGE_SIZE);
		int size = recvfrom(fd, package, RECV_PACKAGE_SIZE, 0, 
				(struct sockaddr *)&src_addr, &length);
		if(size == -1){
			break;
		}
		tcp = (TCP_HEADER *)(package + TCP_HEADER_SIZE);

		if(size < (MIN_PSD_HEADER_SIZE + MIN_TCP_HEADER_SIZE)){
			continue;
		}
		if(ntohs(tcp->des_port) != SRC_PORT){
			continue;
		}
		if(tcp.SYN == 1 && tcp.ACK == 1){
			sendSyn(tcp->src_port, 4);
			printf("port %d is open! because of ACK AND SYN is true", ntohs(tcp.src_port));
		}
	}
}

uint16_t checkSum(uint16_t *addr, int len){
	int sum = 0;
	int nleft = len;
	uint8_t answer = 0;

	while(nleft > 1){
		sum += *addr;
		*addr++;
		nleft -= 2;
	}

	if(nleft == 1){
		*(uint8_t *)&answer = *(uint8_t *)addr;
		sum += answer;
	}
	
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;

	return answer;
}
