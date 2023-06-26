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
void* send_message (void *sock);
void* process();
int init_socket(char* IP_des,int Port_src,char* message,char* pubkey_addr, char* prikey_addr);
int PCGen(char* pubkey_addr, char* prikey_addr);
int KeyGen(EC_KEY *ec_key, char* prikey_addr);
int base64_encode(char in_str[], int in_len, char out_str[]);
int base64_decode(char in_str[], int in_len, char out_str[]);
int Sign(EC_KEY *ec_key, unsigned char *sig, const unsigned char digest[], int digest_len);
int SignMain(EC_KEY *ec_key, unsigned char message[], unsigned char *signature, int *sig_len);
int EVP(unsigned char message[],unsigned char digest[], unsigned int *digest_len);
int message_sign(unsigned char beacon[], unsigned char base64message[], int flag, char* prikey_addr, char* pubkey_addr);
typedef struct Link{
    char* str;
    struct Link *next;
} queue;
struct valid_PC{
        struct valid_PC* next;
        char* KeyID;
        char* ts;
        char* te;
        char* pubkey;
};
struct HashTable_PC{
        struct valid_PC** table;
};

queue * initLink();
queue * insertElem(queue * p,char* msg);
static unsigned int hash_33(char* key);
struct HashTable_PC* hash_table_new();
int hash_table_input(struct HashTable_PC* ht, char* key, char* ts, char* te, char* pubkey);
int hash_table_get(struct HashTable_PC* ht, char* key, char* pubkey);
int decryption(unsigned char* base64_receive, struct HashTable_PC* Pcert);
int verify(EC_KEY *ec_key, const unsigned char *sig, int siglen, unsigned char message[]);
#endif
