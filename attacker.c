#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>
#include "BaselineSend.h"
#include "BaselineReceive.h"

#define Port_src 8885
#define Port_des 8888
#define IP_src INADDR_ANY
#define IP_des "192.168.1.255" //Broadcast address
//#define test_message "MESSAGEMESSAGEMESSAGEMESSAGEMESSAGEMESSAGEMESSAGEMESSAGEMESSAGEMESSAGEMESSAGEMESSAGEMESSAGEMESSAGEMESSAGEMESSAGEMESSAGEMESSAGEMESSAGEMESSAGEMESSAGEMESSAGEMESSAGEMESSAGEMESSAGEMESSAGEMESSAGEMESSAGEMESSAGEMESSAGEMESSAGEMESSAGEMESSAGEMESSAGEMESSAGEMESSAGEMESSAGEMESSAGEMESSAGEMESSAGE"
#define test_message "1"
#define data_file "msg_delay.txt"
#define size_message 1024
#define interval_sending_ms 0 //Interval between two sending messages. The queue will pile when < 10ms
#define size_queue_max 10000
#define BILLION 1000000000.0
#define MILLION 1000000.0
#define THOUSAND 1000.0

/*Define the structure of socket*/
typedef struct struct_send_sock{
	int sock; //socket descriptor
	struct sockaddr_in addr_this;
	int addr_len_this;
} Sock_this;

typedef struct struct_recv_sock{
	int sock;
	struct sockaddr_in addr_target;
	int addr_len_target;
} Sock_target;

/*Linked list structure*/
typedef struct Link{
    char* str;
    struct Link *next;
} link_list;

/*Functions definition*/
int get_socket();
void* recv_message (void *sock);
void* send_message (void *sock);
void* process();
int init_socket();
void display(link_list *p);

/*Global variables*/
Sock_this sock_this = {-1};
Sock_target sock_target = {-1};
int cnt_link = 1;
pthread_mutex_t mut;
struct timespec time_recv[size_queue_max];
struct timespec time_end[size_queue_max];
double msg_delay[size_queue_max];
int cnt_msg_recv = 0;
int cnt_msg_end = 0;
struct timespec time_PC_gen;

int main(int argc, char* argv[]) {
	//printf("Start!\n");

	//Initiate sockets
	init_socket();
	Sock_this *socket_this = &sock_this;
	Sock_target *socket_target = &sock_target;

	//Initiate linked list
	void *send_message(void*);

	//Create 3 threads
	pthread_t th_recv, th_send, th_process;

	pthread_create(&th_send, NULL, send_message, (void *)socket_target);
	pthread_join(th_send, NULL);

	//printf("End!\n");
	return 0;
}

/*Function to create sockets*/
int get_socket(){
	int socket_des = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	//AF_NNET: IPv4; SOCK_DGRAM: datagrams (connectionless, unreliable messages of a fixed maximum length for UDP);.
	return socket_des;
}

/*Function to send messages*/
void* send_message (void *sock){
	int number=0;
	Sock_target *sock_target = (Sock_target *)sock;
	char message_base64_send[size_message] = "k|=|=|p|1|M|j|B|2|2|M|3";
	//BaseLineSendMain(message_send, message_base64_send); //Generate and get the whole Base64 message
	//PCGen();
	while(1){
		//printf("Start sending.\n");
		if (sendto(sock_target->sock, message_base64_send, strlen(message_base64_send)+1, 0,
				(struct sockaddr *)&(sock_target->addr_target), sock_target->addr_len_target )  < 0){
			printf("Sending failed.\n");
			exit(1);
		}
/*		if ( !strcmp(message_send,"test")){
			break;
		}
*/		number++;
		//printf("Message sent: %s\n", message_base64_send);
		usleep(interval_sending_ms*1000); //Sleep for some time
		if(number%100==0)
		{
			printf("%d\n",number);
		}
	}
	close(sock_target->sock);
}

/*Function to initiate sockets*/
int init_socket(){

	//Create socket descriptor
	sock_this.sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	sock_target.sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	//Check if creating successfully
	if (sock_this.sock < 0 || sock_target.sock < 0 ){
		printf("Initiating sockets failed.\n");
		exit(1);
	}

	//Set broadcast
	int set = 1;
	if (setsockopt(sock_this.sock, SOL_SOCKET, SO_BROADCAST, &set, sizeof(set)) == -1) {
	    printf("setsockopt failed.\n");
	    exit(1);
	}
	if (setsockopt(sock_target.sock, SOL_SOCKET, SO_BROADCAST, &set, sizeof(set)) == -1) {
		printf("setsockopt failed.\n");
		exit(1);
	}

	//Set address
	memset(&sock_this.addr_this, 0, sizeof(sock_this.addr_this)); //Clear memory
	memset(&sock_target.addr_target, 0, sizeof(sock_target.addr_target));
	sock_this.addr_this.sin_port = htons(Port_src); //Convert the unsigned short integer from host byte order to network byte order
	sock_this.addr_this.sin_addr.s_addr = INADDR_ANY; //Set the address INADDR_ANY instead of indicating the exact address number
	sock_this.addr_this.sin_family = AF_INET;   //Use IPv4

	sock_target.addr_target.sin_port = htons(Port_des);
	sock_target.addr_target.sin_addr.s_addr = inet_addr(IP_des); //Convert the unsigned short integer from host byte order to network byte order
	sock_target.addr_target.sin_family = AF_INET;   //Use IPv4

	sock_this.addr_len_this = sizeof(struct sockaddr_in);
	sock_target.addr_len_target = sizeof(struct sockaddr_in);

	//Bind the address to the socket referred by the descriptor
	if (bind(sock_this.sock, (struct sockaddr*)&(sock_this.addr_this), sizeof(struct sockaddr)) < 0){
		printf("Bind failed.\n");
		exit(1);
	}
	printf("Sockets initiated!\n");
	return 0;
}
