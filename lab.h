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
#define MAXSIGLEN 1024
#define TABLE_SIZE 1000
#define rsu_key_initial "1d5c6ed404b9a1f19e6830a098cd481f08a8f6355993a5e89a1067808d058a86"
void* recv_message (void *sock);
void* send_message (void *sock);
void* process();
int init_socket(char* IP_des,int Port_src,char* message,char* pubkey_addr, char* prikey_addr);
int PCGen(unsigned char* prikey_addr, unsigned char* pubkey_addr);
int KeyGen(EC_KEY *ec_key, char* prikey_addr);
int base64_encode(char in_str[], int in_len, char out_str[]);
int base64_decode(char in_str[], int in_len, char out_str[]);
int Sign(EC_KEY *ec_key, unsigned char *sig, const unsigned char digest[], int digest_len);
int SignMain(EC_KEY *ec_key, unsigned char message[], unsigned char *signature, int *sig_len);
int EVP(unsigned char message[],unsigned char digest[], unsigned int *digest_len);
int message_sign(unsigned char beacon[], unsigned char base64message[], int flag, unsigned char* prikey_addr, unsigned char* pubkey_addr);

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

typedef struct Link{
    char* str;
    struct Link *next;
} queue;

queue * initLink();
queue * insertElem(queue * p,char* msg);
static unsigned int hash_33(char* key);
struct HashTable_PC* hash_table_new();
int hash_table_input(struct HashTable_PC* ht, unsigned char* key, unsigned char* ts, unsigned char* te, unsigned char* pubkey);
int hash_table_get(struct HashTable_PC* ht, char* key, char* pubkey);
int decryption(unsigned char* base64_receive, struct HashTable_PC* Pcert);
int verify(EC_KEY *ec_key, const unsigned char *sig, int siglen, unsigned char message[]);
int message_process(unsigned char base64_receive[], struct HashTable_PC* ht);
#endif
