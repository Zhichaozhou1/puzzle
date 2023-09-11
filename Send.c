#include "lab.h"
extern struct timespec time_PC_gen;
int message_sign(unsigned char beacon[], unsigned char base64message[], int flag, unsigned char* prikey_addr, unsigned char* pubkey_addr)
{
        char *random_seed = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        int seed_length = strlen(random_seed);
        char ss[2] = {'\0'};
        unsigned char beacon_signature_buff[1024]={'\0'};
        unsigned char* beacon_signature_buff_pp = beacon_signature_buff;
        unsigned char Base64Message[1024]={'\0'};
        unsigned char beacon_signature_buff_base64[1024]={'\0'};
        unsigned char PC_encode[1024] = {'\0'};
        unsigned char hash_beacon[1024] = {'\0'};
        unsigned char hash_beacon_encode[1024] = {'\0'};
        int hash_beacon_length;
        int beacon_len = strlen(beacon);
        int beacon_sig_len = 0;
        //int find_solution = 0;
        /* Read private key form prikey.pem */
        FILE *f = fopen(prikey_addr, "r");
        EC_KEY *ec_prikey = PEM_read_ECPrivateKey(f, NULL, NULL, NULL);
        fclose(f);
        if (ec_prikey == NULL)
                {
                printf("Error：PEM_read_ECPrivateKey()\n");
                return 0;
        }
        /* Sign beacon with kv */
        if(!SignMain(ec_prikey, beacon, beacon_signature_buff_pp, &beacon_sig_len))
        {
                printf("Error: SignMain()\n");
                return 0;
        }
        /* Send beacon in plaintext */
        strcpy(Base64Message, beacon);
        strcat(Base64Message,"|");
        /* Encode beacon signature */
        base64_encode(beacon_signature_buff, beacon_sig_len, beacon_signature_buff_base64);
        strcat(Base64Message, beacon_signature_buff_base64);
        /* Read PC Base64 file */
        FILE *fp = fopen(pubkey_addr, "r");
        fgets(PC_encode, 1024, fp);
        fclose(fp);
        if (flag==1)
        {
                strcat(Base64Message, PC_encode);
        }
        else
        {
                unsigned char KeyID[9]={'\0'};
                for(int i=0;i<8;i++)
                {
                        KeyID[i]=PC_encode[i];
                }
                strcat(Base64Message, KeyID);
        }
        for(int i = 1; i <= 8; i++){
                sprintf(ss,"%c",random_seed[(rand()%seed_length)]);
                strcat(Base64Message,ss);
        }
        int beacon_length = strlen(Base64Message);
        while(1)
        {
                EVP(Base64Message,hash_beacon, &hash_beacon_length);
                for (int j = 0; j < 32 ; j++){
                        snprintf(hash_beacon_encode+2*j, 64+1-2*j, "%02x", hash_beacon[j]);
                }
                if(hash_beacon_encode[63]=='0'&&hash_beacon_encode[62]=='0')//&&(digest_encode[61]=='0'))
                {
                        break;
                }
                if(Base64Message[beacon_length-1]!='z')
                {
                        Base64Message[beacon_length-1] = Base64Message[beacon_length-1] + 1;
                }
                else if(Base64Message[beacon_length-2]!='z')
                {
                        Base64Message[beacon_length-1] = '!';
                        Base64Message[beacon_length-2] = Base64Message[beacon_length-2] + 1;
                }
                else
                {
                        Base64Message[beacon_length-1] = '!';
                        Base64Message[beacon_length-2] = '!';
                        Base64Message[beacon_length-3] = Base64Message[beacon_length-3] + 1;
                }
        }
        strcpy(base64message, Base64Message);
        return 1;
}

/*****************************************************************************
 * Function Name: base64_encode
 * Description: Encode message in Base64 format, encode message ended with '|'
 * @ in_str:  Input string
 * @ in_len:  Input string length
 * @ out_str: Output string length
 *
 * Return
 * @ size: Base64 message length
 * @ 0: Function Error
*/
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
        // out_str[bptr->length] = '\0';
        out_str[bptr->length] = '|';
        size = bptr->length;
        BIO_free_all(bio);
        return size;
}

/*****************************************************************************
 * Function Name: EVP
 * Description: Hash message in SHA256
 * Parameter
 * @ message:    Massger for Hash
 * @ digest:     Part of hashed message
 * @ digest_len: Length of digest string
 * Return
 * @ 1: Function runs correctly
 * @ 0: Function Error
*/
int EVP(unsigned char message[],unsigned char digest[], unsigned int *digest_len)
{
        EVP_MD_CTX *md_ctx;
        md_ctx = EVP_MD_CTX_new();
        int message_len = strlen(message);
        if(!EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL))                                          // Return 1 on success, 0 on error
        {
                printf("Error：EVP_DigestInit_ex\n");
                return 0;
        }
        if(!EVP_DigestUpdate(md_ctx, (const void *)message, message_len))
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

/*****************************************************************************
 * Function Name: KeyGen
 * Description: Generate public/private key pairs, and out put in file.
 * Parameter
 * @ ec_key:   Structure storing pu/pr keys and curve parameters
 *
 * File
 * @ ec_group: Structure associate curve and store curve parameters
 * @ prikey.pem: Private key file
 *
 * Return
 * @ 1: Function runs correctly
 * @ 0: Function Error
*/

int KeyGen(EC_KEY *ec_key, char* prikey_addr)
{
        /* Set Param for print keys */
        unsigned char buf[1024];
        unsigned char *pp;
        int i,len;
        /* Declare structures */
        EC_GROUP *ec_group;
        /* Choose an elliptic curve */
        ec_group = EC_GROUP_new_by_curve_name(NID_brainpoolP256r1);        // Curve: Prime 256 v1
        if (ec_group == NULL)
        {
                printf("Error：EC_GROUP_new_by_curve_name()\n");
                EC_KEY_free(ec_key);
                return 0;
        }
        /* Set key parameters */
        int ret;
        ret = EC_KEY_set_group(ec_key,ec_group);                            // Return 1 on success, 0 on error
        if(ret != 1)
        {
                printf("Error：EC_KEY_set_group()\n");
                return 0;
        }
        /* Generate key pair */
        if (!EC_KEY_generate_key(ec_key))                                   // Return 1 on success, 0 on error
        {
                printf("Error：EC_KEY_generate_key()\n");
                EC_KEY_free(ec_key);
                return 0;
        }
        /* Save the private key and public key */
        FILE *pri_stream;
        if ((pri_stream = fopen(prikey_addr, "w")) == NULL)
        {
                perror("fail to write");
                exit(1);
        }
        PEM_write_ECPrivateKey(pri_stream, ec_key, NULL, NULL, 0, NULL, NULL);
        fclose(pri_stream);
        /* Print key for debug */
        /* Print Private Key */
        pp = buf;
        len = i2d_ECPrivateKey(ec_key,&pp);
        if (!len)
        {
                printf("Error：i2d_ECPrivateKey()\n");
                EC_KEY_free(ec_key);
                return -1;
        }
        /* Print Public Key */
        pp = buf;
        len = i2o_ECPublicKey(ec_key,&pp);
        if (!len)
        {
                printf("Error：i2o_ECPublicKey()\n");
                EC_KEY_free(ec_key);
                return -1;
        }
        return 1;
}

/**
 * Function Name: PCGen
 * Description: Generate pseudonym certificate in base64 format, save certificate
 * in file
 * Base Line message structure: beacon||beacon_sig||Kv||Cert(Kv)
 * Pseudonym Certificate Structure: (KeyID||ts||te||Kv) sign with CA private key
 * KeyID: PC identity message, 4 byte Kv hash
 * ts: Start validation time
 * te: End validation time
 * Kv: ECDSA public key
 * Cert(Kv): pseudonym certificate
 *
 * Parameters:
 * @ ec_key: Structure storing pu/pr keys and curve parameters
 *
 * File:
 * @ pc.pem: Encoded Pseudonym Certificate
 *
 * Return
 * @ 1: Function runs correctly
 * @ 0: Function Error
*/

int PCGen(unsigned char* prikey_addr,unsigned char* pubkey_addr)
{
        EC_KEY *ec_key;
        int i;
        int j;
        int message_len;
        int pubkey_len;
        int sig_len = 0;
        unsigned char KeyID[32]={'\0'};
        unsigned char *pubkey_buff_pp;                              // Pointer to to temp pubkey address
        unsigned char *message_pp;
        unsigned char pubkey_buff[128] = {'\0'};                    // Declare public key buffer and preset to 0
        unsigned char signature_buff[MAXSIGLEN] = {'\0'};
        unsigned char* signature_buff_pp = signature_buff;
        pubkey_buff_pp = pubkey_buff;
        /* Construct ec_key */
        ec_key = EC_KEY_new();                                          // The newly created EC_KEY is initially set to 1
        if (ec_key == NULL)
        {
                printf("Error：EC_KEY_new()\n");
                return 0;
        }
        /* Generate Key Pair */
        if(!KeyGen(ec_key,prikey_addr))                                             // Return 1 on success, 0 on error
        {
                printf("Error: KeyGen()\n");
                return 0;
        }
        /* Read CA's private key from keyfile*/
        FILE *f = fopen("privatekey.pem", "r");
        EC_KEY *cert_key = PEM_read_ECPrivateKey(f, NULL, NULL, NULL);
        fclose(f);
        if (cert_key == NULL)
        {
                printf("Error：PEM_read_ECPrivateKey()\n");
                return 0;
        }
        /* Get start time and end time */
        clock_gettime(CLOCK_REALTIME, &time_PC_gen);
        time_t t = time_PC_gen.tv_sec;                              // Get current time from 1970-01-01, count on seconds
        int ts = time(&t) / 60 -2;                                     // start time, count on minutes
        int te = ts + 129600;                                           // end time 15 minutes
        // int te = ts + 129600;                                    // end time, 90 days,(129,600 minutes)
        unsigned char ts_string_temp[16] = {'\0'};
        unsigned char te_string_temp[16] = {'\0'};
        unsigned char ts_string[16] = {'\0'};
        unsigned char te_string[16] = {'\0'};
        sprintf(ts_string_temp, "%d", ts);
        sprintf(te_string_temp, "%d", te);
        strcpy(ts_string, ts_string_temp);
        strcpy(te_string, te_string_temp);
        int keyID_len = 0;
        int ts_string_len = strlen(ts_string);
        int te_string_len = strlen(te_string);
        /* Get ECDSA public key and its length */
        pubkey_len = i2o_ECPublicKey(ec_key, &pubkey_buff_pp);      // Encode Pubkey in Hexadecimal string, return key length not include '\0'
        unsigned char pubkey[pubkey_len];
        for(i = 0; i < pubkey_len; i++)                             // Consider '\0' may exist in middle, use for to assigen value
        {
                pubkey[i] = pubkey_buff[i];
        }
        /* Generate KeyID */
        if(!EVP(pubkey, KeyID, &keyID_len))
        {
                printf("Error：EVP()\n");
                return 0;
        }
        message_len = 4 + ts_string_len + te_string_len + pubkey_len;
        unsigned char message[message_len];
        for(i = 0; i < 4; i++)
        {
                message[i] = KeyID[i];
        }
        for(i = 4, j = 0; j < ts_string_len; i++, j++)
        {
                message[i] = ts_string[j];
        }
        for(i = 4 + ts_string_len, j = 0; j < te_string_len; i++, j++)
        {
                message[i] = te_string[j];
        }
        for(i = 4 + ts_string_len + te_string_len, j = 0; j < pubkey_len; i++, j++)
        {
                message[i] = pubkey[j];
        }
        /* Sign Pseudonym */
        if(!SignMain(cert_key, message, signature_buff_pp, &sig_len))
        {
                printf("Error: SignMain()\n");
                return 0;
        }
        /* Encode Pseudonym Certificate in Base64
        * str1: Key ID
        * str2: Public Key Kv
        * str3: Begin time ts
        * str4: End time te
        * str5: Certificate Signature
        */
        unsigned char EncodeMessage[1024] = {'\0'};
        unsigned char str1[1024] = {'\0'};
        unsigned char str2[1024] = {'\0'};
        unsigned char str3[1024] = {'\0'};
        unsigned char str4[1024] = {'\0'};
        unsigned char str5[1024] = {'\0'};
        int str_len = 0;
        str_len = base64_encode(KeyID, 4, str1);
        strcpy(EncodeMessage, str1);
        str_len = base64_encode(pubkey, pubkey_len, str2);
        strcat(EncodeMessage, str2);
        strcpy(str3, ts_string);
        strcat(str3, "|");
        strcat(EncodeMessage, str3);
        strcpy(str4, te_string);
        strcat(str4, "|");
        strcat(EncodeMessage, str4);
        str_len = base64_encode(signature_buff,sig_len, str5);
        strcat(EncodeMessage, str5);
        //printf("Base64 encode message:\n%s", EncodeMessage);
        /* Write Pseudonym Certificate in File */
        FILE *PC_stream;
        if ((PC_stream = fopen(pubkey_addr, "w")) == NULL)
        {
                perror("fail to write");
                exit(1);
        }
        fputs(EncodeMessage, PC_stream);
        fclose(PC_stream);
        return 1;
}

/*****************************************************************************
 * Function Name: SignMain
 * Description: Main function for signatuer
 *
 * Parameter
 * @ ec_key:     Private key for signature
 * @ message:    Message for signature
 * @ signature:  Signature storage buffer
 * @ sig_len:    Signature length
 *
 * Return
 * @ 1: Function success
 * @ 0: Function error
*/

int SignMain(EC_KEY *ec_key, unsigned char message[], unsigned char *signature, int *sig_len)
{
        int i;
        int len;
        unsigned char digest[32]={};
        unsigned int digest_len = 0;
        if(!EVP(message, digest, &digest_len))
        {
                printf("Error：EVP\n");
                return 0;
        }
        len  = Sign(ec_key, signature, digest, digest_len);
        if (len == -1)                                                  // Retrun -1 for error
        {
                printf("Error：Sign\n");
                return 0;
        }
        /* Assign len value to sig_len*/
        int *pa = &len;
        int *pb = sig_len;
        *pb = *pa;
        return 1;
}

/*****************************************************************************
 * Function Name: Sign
 * Description: Sing digest message with ECDSA private key, write it in char.
 * Parameter
 * @ ec_key:     Sturcture stroes private key
 * @ sig:        Pointer to store signature.
 * @ digest:     Part of hashed message
 * @ digest_len: Length of digest string
 * Return
 * @ sign_len: Length of signature
 * @ -1: Function error
*/

int Sign(EC_KEY *ec_key, unsigned char *sig, const unsigned char digest[], int digest_len)
{
        unsigned int sign_len = MAXSIGLEN;
        if (!ECDSA_sign(0, digest, digest_len, sig, &sign_len, ec_key))
        {
                printf("Error：ECDSA_sign()\n");
                EC_KEY_free(ec_key);
                return -1;
        }
        return sign_len;
}
