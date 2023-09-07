#include "lab.h"

//define socket parameters
#define Port_des 8888
#define IP_src 192.168.1.218 //source ip address
//#define IP_dest "130.237.20.255"
#define size_message 1024
#define size_queue_max 80000
#define interval_sending_ms 100 //Interval between two sending messages
#define BILLION 1000000000.0
#define MILLION 1000000.0
#define THOUSAND 1000.0
/*Define the structure of socket*/
typedef struct struct_send_sock{
        int sock; //socket descriptor
        struct sockaddr_in addr_this;
        int addr_len_this;
        char* pubkey_addr;
} Sock_this;

typedef struct struct_recv_sock{
        int sock;
        struct sockaddr_in addr_target;
        int addr_len_target;
        int Port_src;
        char* message;
        char* prikey_addr;
        char* pubkey_addr;
} Sock_target;

Sock_this sock_this = {-1};
Sock_target sock_target = {-1};
struct HashTable_PC* ht;
queue *queue_msg_header = NULL; //linked list header
queue *queue_msg_rear = NULL; //linked list rear
struct timespec time_PC_gen;
struct timespec time_recv[size_queue_max];
struct timespec time_process[size_queue_max];
struct timespec time_end[size_queue_max];
double msg_delay[size_queue_max];
int cnt_msg_recv = 0;
int cnt_msg_end = 0;
int valid_msg_end = 0;
int main(int argc, char* argv[]){
        char* message = argv[1];
        char* IP_des = argv[2];
        int Port_src = atoi(argv[3]);
        char* pubkey_addr = argv[4];
        char* prikey_addr = argv[5];
        init_socket(IP_des,Port_src,message,pubkey_addr,prikey_addr);
        Sock_this *socket_this = &sock_this;
        Sock_target *socket_target = &sock_target;
        queue_msg_header = initLink();
        queue_msg_rear = queue_msg_header;
        ht = hash_table_new();
        void *recv_message(void*);
        void *send_message(void*);
        //Create 3 threads
        pthread_t th_recv, th_send, th_process;
        pthread_create(&th_send, NULL, send_message, (void *)socket_target);
        pthread_create(&th_recv, NULL, recv_message, (void *)socket_this);
        pthread_create(&th_process, NULL, process, NULL);
        pthread_join(th_recv, NULL);
        pthread_join(th_send, NULL);
        pthread_join(th_process, NULL);
        return 0;
}

/*Function to initiate sockets*/
int init_socket(char* IP_des,int Port_src,char* message,char* pubkey_addr, char* prikey_addr)
{
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
        sock_this.pubkey_addr = pubkey_addr;

        sock_target.addr_target.sin_port = htons(Port_des);
        sock_target.addr_target.sin_addr.s_addr = inet_addr(IP_des); //Convert the unsigned short integer from host byte order to network byte order
        sock_target.addr_target.sin_family = AF_INET;   //Use IPv4
        sock_target.message = message;
        sock_target.prikey_addr = prikey_addr;
        sock_target.pubkey_addr = pubkey_addr;

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

/*Function to receive messages*/
void* recv_message (void *sock){
        Sock_this *sock_this = (Sock_this *)sock;
        struct sockaddr_in addr_others;
        char message_recv[size_message] = {'\0'}; //Buffer storing received messages
        while(1){
                int flag;
                flag = recvfrom(sock_this->sock, message_recv, size_message, 0,
                                                                (struct sockaddr *)&addr_others, (socklen_t *)&(sock_this->addr_len_this));
                //the 4th argument is the source IP address
                //recvfrom returns the number of bytes received, but -1 when errors.
                if (flag >= 0){
                        printf("Message received: %s\n",message_recv);
                        clock_gettime(CLOCK_REALTIME, &(time_recv[cnt_msg_recv]));
                        cnt_msg_recv++;
                } else {
                        printf("Receiving failed.\n");
                    exit(1);
                }
                queue_msg_rear = insertElem(queue_msg_rear, message_recv);
        }
        close(sock_this->sock);
}

/*Function to send messages*/
void* send_message (void*sock){
        Sock_target *sock_target = (Sock_target *)sock;
        char* message_send = sock_target->message;
        printf("%s\n",message_send);
        char message_base64_send[size_message] = {'\0'};
        PCGen(sock_target->prikey_addr,sock_target->pubkey_addr);
        //BaseLineSendMain(message_send, message_base64_send); //Generate and get the whole Base64 message
        while(1){
                message_sign(message_send,message_base64_send,1,sock_target->prikey_addr,sock_target->pubkey_addr);
                if (sendto(sock_target->sock, message_base64_send, strlen(message_base64_send), 0,
                                (struct sockaddr *)&(sock_target->addr_target), sock_target->addr_len_target )  < 0){
                        printf("Sending failed.\n");
                        printf("Error sending packet: Error %d.\n", errno);
                        exit(1);
                }
                printf("message send:%s\n",message_base64_send);
                usleep(interval_sending_ms*1000);
        }
        close(sock_target->sock);
}

void *process(){
        int num=0;
        while(1){
                int expire=0;
                //Skip the process if there is no message in the linked list (header->next is NULL)
                if (queue_msg_header->next==NULL){
                        continue;
                }
                clock_gettime(CLOCK_REALTIME, &(time_process[cnt_msg_end]));
                queue *temp = queue_msg_header;
                queue *temp_plus = queue_msg_header;
                char *msg_temp = temp->next->str;
                int flag = 0;
                if(((time_process[cnt_msg_end].tv_sec- time_recv[cnt_msg_end].tv_sec)*1000 + (time_process[cnt_msg_end].tv_nsec - time_recv[cnt_msg_end].tv_nsec)/MILLION)<1000)
                {
                        flag = message_process(msg_temp, ht); //Verify messages
                }
                if (flag == 1){
                        num++;
                        printf("Verification successful!\n");
                } else if (flag == 0){
                        num++;
                        printf("Verification failed!\n");
                } else if (flag == -1){
                        printf("Other errors.\n");
                }
                //Get the end time of messages
                clock_gettime(CLOCK_REALTIME, &(time_end[cnt_msg_end]));
                if(flag==1){
                        msg_delay[valid_msg_end] = (time_end[cnt_msg_end].tv_sec- time_recv[cnt_msg_end].tv_sec)*1000 + (time_end[cnt_msg_end].tv_nsec - time_recv[cnt_msg_end].tv_nsec)/MILLION;
                        valid_msg_end++;
                }
                cnt_msg_end++;
                int cnt_nodes = 0;
                while (temp_plus->next != NULL){
                        cnt_nodes++;
                        temp_plus = temp_plus->next;
                }
                queue_msg_header = queue_msg_header->next;
                queue_msg_header->str = NULL;
                free(temp);
                /*if (flag==1){
                        FILE *fp = fopen(data_file, "wb");
                        for (int i = 0; i < valid_msg_end; i++) {
                            fprintf(fp, "%d %fms\n", i, msg_delay[i]);
                            // check for error here too
                        }
                        fclose(fp);
                }*/
        }
}

queue * initLink(){
        queue * p=(queue*)malloc(sizeof(link));//create the header
        p->str = NULL;
        p->next = NULL;
        return p;
}

/*Function to insert element*/
queue * insertElem(queue * p,char* msg){
        queue * temp=(queue*)malloc(sizeof(queue));
        char *msg_temp = (char *)malloc((strlen(msg)+1)*1);
        strcpy(msg_temp, msg);
        temp->str = msg_temp;
        temp->next = NULL;
        p->next = temp;
        p=p->next;
        return  p;
}
