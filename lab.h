#ifndef LAB_H
#define LAB_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/buffer.h>
#include <time.h>

void* recv_message (void *sock);
void* send_message (char* message_send,void* sock);
void* process();
int init_socket(char* IP_des);
typedef struct Link{
    char* str;
    struct Link *next;
} queue;
queue * initLink();
queue * insertElem(queue * p,char* msg);


#endif
