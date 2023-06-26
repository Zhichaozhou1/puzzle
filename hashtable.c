#include "lab.h"
#define TABLE_SIZE 1000

static unsigned int hash_33(char* key)
{
    unsigned int hash = 0;
    while (*key) {
        hash = (hash << 5) + hash + *key++;
    }
    return hash;
}

struct HashTable_PC* hash_table_new()
{
    struct HashTable_PC* ht = malloc(sizeof(struct HashTable_PC));
    if (NULL == ht) {
        return NULL;
    }
    ht->table = malloc(sizeof(struct valid_PC*) * TABLE_SIZE);
    if (NULL == ht->table) {
        return NULL;
    }
    memset(ht->table, 0, sizeof(struct valid_PC*) * TABLE_SIZE);
    return ht;
}

int hash_table_input(struct HashTable_PC* ht, char* key, char* ts, char* te, char* pubkey){
        printf("1");
        int i = hash_33(key) % TABLE_SIZE;
        struct valid_PC* p = ht->table[i];
        struct valid_PC* prep = p;
        while(p){
                p=p->next;
        }
        if(p==NULL)
        {
                char* keystr = malloc(strlen(key)+1);
                char* tsstr = malloc(strlen(ts)+1);
                char* testr = malloc(strlen(te)+1);
                char* pubkeystr = malloc(strlen(pubkey)+1);
                struct valid_PC* valid_PC = malloc(sizeof(struct valid_PC));
                valid_PC->next == NULL;
                strcpy(keystr,key);
                strcpy(tsstr,ts);
                strcpy(testr,te);
                strcpy(pubkeystr,pubkey);
                valid_PC->KeyID = keystr;
                valid_PC->ts = tsstr;
                valid_PC->te = testr;
                valid_PC->pubkey = pubkeystr;
                prep->next = valid_PC;
        }
        return 0;
}

int hash_table_get(struct HashTable_PC* ht, char* key, char* pubkey){
        int i = hash_33(key) % TABLE_SIZE;
        struct valid_PC* p = ht->table[i];
        while(p)
        {
                if (strcmp(key, p->KeyID) == 0) {
                        strcpy(pubkey,p->pubkey);
                        return 1;
                }
                p = p->next;
        }
        return 0;
}
