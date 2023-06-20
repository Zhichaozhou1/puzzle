#include "lab.h"

//define socket parameters
#define Port_src 8888
#define Port_des 8888
#define IP_src INADDR_ANY //source ip address
//#define IP_dest "130.237.20.255"
#define size_message 1024
#define interval_sending_ms 100 //Interval between two sending messages

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

Sock_this sock_this = {-1};
Sock_target sock_target = {-1};
queue *queue_msg_header = NULL; //linked list header
queue *queue_msg_rear = NULL; //linked list rear

int main(int argc, char* argv[]){
        char* message = argv[1];
        char* IP_des = argv[2];
        init_socket(IP_des);
        Sock_this *socket_this = &sock_this;
        Sock_target *socket_target = &sock_target;
        queue_msg_header = initLink();
        queue_msg_rear = queue_msg_header;
        void *recv_message(void*);
        void *send_message(char* message_send,void*);
        void* sock;
        //Create 3 threads
        pthread_t th_recv, th_send, th_process;
        pthread_create(&th_send, NULL, send_message(message,sock), (void *)socket_target);
        pthread_create(&th_recv, NULL, recv_message, (void *)socket_this);
        //pthread_create(&th_process, NULL, process, NULL);
        pthread_join(th_recv, NULL);
        pthread_join(th_send, NULL);
        //pthread_join(th_process, NULL);
        return 0;
}

/*Function to initiate sockets*/
int init_socket(char* IP_des){

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

/*Function to receive messages*/
void* recv_message (void *sock){
        Sock_this *sock_this = (Sock_this *)sock;
        struct sockaddr_in addr_others; //The address used to send messages
        char message_recv[size_message] = {'\0'}; //Buffer storing received messages
        while(1){
                //printf("Start receiving.\n");
                int flag;
                flag = recvfrom(sock_this->sock, message_recv, size_message, 0,
                                                                (struct sockaddr *)&addr_others, (socklen_t *)&(sock_this->addr_len_this));
                //the 4th argument is the source IP address
                //recvfrom returns the number of bytes received, but -1 when errors.
                if (flag >= 0){
                        printf("Message received: %s\n",message_recv);
                } else {
                        printf("Receiving failed.\n");
                    exit(1);
                }
                queue_msg_rear = insertElem(queue_msg_rear, message_recv);
        }
        close(sock_this->sock);
}

/*Function to send messages*/
void* send_message (char* message_send, void*sock){
        Sock_target *sock_target = (Sock_target *)sock;
        printf("%s\n",message_send);
        //char message_base64_send[size_message] = {'\0'};
        //BaseLineSendMain(message_send, message_base64_send); //Generate and get the whole Base64 message
        while(1){
                if (sendto(sock_target->sock, message_send, strlen(message_send), 0,
                                (struct sockaddr *)&(sock_target->addr_target), sock_target->addr_len_target )  < 0){
                        printf("Sending failed.\n");
                        printf("Error sending packet: Error %d.\n", errno);
                        exit(1);
                }
                usleep(interval_sending_ms*1000);
        }
        close(sock_target->sock);
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
