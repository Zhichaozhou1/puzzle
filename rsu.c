#include "lab.h"

#define Port_src 8000
#define Port_des 8888
#define IP_src INADDR_ANY
#define IP_des "192.168.1.255" //Broadcast address
#define size_message 1024
#define keychain_length 1000
#define test_seed "seed to test the rsu"
#define interval_sending_ms 100 //Interval between two sending messages. The queue will pile when < 10ms
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

/*Functions definition*/
void* send_message (void *sock);
int init_socket_rsu();

/*Global variables*/
Sock_this sock_this = {-1};
Sock_target sock_target = {-1};

int main(int argc, char* argv[]) {
        //printf("Start!\n");

        //Initiate sockets
        init_socket_rsu();
        Sock_this *socket_this = &sock_this;
        Sock_target *socket_target = &sock_target;

        //Initiate linked list
        void *send_message(void*);

        //Create 3 threads
        pthread_t th_send;

        pthread_create(&th_send, NULL, send_message, (void *)socket_target);
        pthread_join(th_send, NULL);

        //printf("End!\n");
        return 0;
}

/*Function to send messages*/
void* send_message (void *sock){
        int number=0;
        int number_send = 0;
        int hash_len = 0;
        unsigned char hash[32] = {'\0'};
        //unsigned char hash_temp[65] = {'\0'};
        unsigned char hash_encode[1001][65] = {'\0'};
        //hash_encode = malloc((keychain_len+1)*sizeof(char*));
        strcpy(hash_encode[0],test_seed);
        Sock_target *sock_target = (Sock_target *)sock;
        for(int i=0; i<keychain_length; i++)
        {
                EVP(hash_encode[i],hash,&hash_len);
                for (int j = 0; j < 32 ; j++){
                        snprintf(hash_encode[i+1]+2*j, sizeof(hash_encode[i+1])-2*j, "%02x", hash[j]);
                }
                //printf("%s\n",hash_encode[i]);
                //base64_encode(hash, hash_len, hash_encode[i+1]);
        }
        while(1){
                //printf("Start sending.\n");
                number_send = number/10;
                if (sendto(sock_target->sock, hash_encode[keychain_length-number_send], strlen(hash_encode[keychain_length-number_send])+1, 0,
                                (struct sockaddr *)&(sock_target->addr_target), sock_target->addr_len_target )  < 0){
                        printf("Sending failed.\n");
                        exit(1);
                }
                //printf("Message sent: %s\n", hash_encode[keychain_length-number_send]);
                number++;
                usleep(interval_sending_ms*1000); //Sleep for some time
        }
        close(sock_target->sock);
}

/*Function to initiate sockets*/
int init_socket_rsu(){

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

int EVP(unsigned char message[],unsigned char digest[], unsigned int* digest_len)
{
        EVP_MD_CTX *md_ctx;
        md_ctx = EVP_MD_CTX_new();

        if(!EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL))                                          // Return 1 on success, 0 on error
        {
                printf("Error：EVP_DigestInit_ex\n");
                return 0;
        }
        if(!EVP_DigestUpdate(md_ctx, (const void *)message, strlen(message)))
        {
                printf("Error：EVP_DigestUpdate\n");
                return 0;
        }

        if(!EVP_DigestFinal(md_ctx, digest, digest_len))
        {
                printf("Error：EVP_DigestFinal\n");
                return 0;
        }

        return 1;
}


int base64_encode(char in_str[], int in_len, char out_str[])
{
        BIO *b64, *bio;
        BUF_MEM *bptr = NULL;
        size_t size = 0;

        if (in_str == NULL || out_str == NULL)
                return 0;

        b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // Do not add "/n" in the end.
        bio = BIO_new(BIO_s_mem());
        bio = BIO_push(b64, bio);

        BIO_write(bio, in_str, in_len);
        BIO_flush(bio);

        BIO_get_mem_ptr(bio, &bptr);
        memcpy(out_str, bptr->data, bptr->length);
        size = bptr->length;

        BIO_free_all(bio);
        return size;
}
