#include "lab.h"

/*****************************************************************************
 * Function Name: BaseLineReceiveMain
 * Description: Main function in base line verification
 *
 * Parameter:
 * @ base64_receive:    Receice base64 message
 * Return
 * @ 1: Verification Success
 * @ 0: Function error
*/
int message_receive(unsigned char base64_receive[], link_list * p)
{
        int i = 0;
        int j;
        char PC_store[1024] = {'\0'};
        char PC_store_KeyID[10] = {'\0'};
        char PC_received_KeyID[10] = {'\0'};
        char* PC_st;
        unsigned char message[1024] = {'\0'};
        unsigned char message_sig[1024] = {'\0'};
        unsigned char KeyID[10] = {'\0'};
        unsigned char pubkey[1024] = {'\0'};
        unsigned char ts[1024] = {'\0'};
        unsigned char te[1024] = {'\0'};
        unsigned char cert_sig[1024] = {'\0'};
        unsigned char zero_buffer[1024] = {'\0'};       // Rewrite buffer to zero
        /* Get receiving message segment */
        for(i = 0, j = 0; i < strlen(base64_receive); i++, j++)
        {
                if(base64_receive[i] != '|')
                {
                        message[j] = base64_receive[i];
                }
                else
                {
                        i++;
                        break;
                }
        }
        for(i, j = 0; i < strlen(base64_receive); i++, j++)
        {
                if(base64_receive[i] != '|')
                {
                        message_sig[j] = base64_receive[i];
                }
                else
                {
                        i++;
                break;
                }
        }
        for(i, j = 0; i < strlen(base64_receive); i++, j++)
        {
                if(base64_receive[i] != '|')
                {
                        KeyID[j] = base64_receive[i];
                }
                else
                {
                i++;
                break;
                }
        }
        for(i, j = 0; i < strlen(base64_receive); i++, j++)
        {
                if(base64_receive[i] != '|')
                {
                        pubkey[j] = base64_receive[i];
                }
                else
                {
                        i++;
                        break;
                }
        }
        for(i, j = 0; i < strlen(base64_receive); i++, j++)
        {
                if(base64_receive[i] != '|')
                {
                        ts[j] = base64_receive[i];
                }
                else
                {
                        i++;
                        break;
                }
        }
        for(i, j = 0; i < strlen(base64_receive); i++, j++)
        {
                if(base64_receive[i] != '|')
                {
                        te[j] = base64_receive[i];
                }
                else
                {
                        i++;
                        break;
                }
        }
        for(i, j = 0; i < strlen(base64_receive); i++, j++)
        {
                if(base64_receive[i] != '|')
                {
                        cert_sig[j] = base64_receive[i];
                }
                else
                {
                        i++;
                        break;
                }
        }
        /* Construct PC base64 message */
        unsigned char separator[2] = {'|'};
        unsigned char PC_base64[1024] = {'\0'};     // The PC_decode is the base64 PC without "|"
        strcpy(PC_base64, KeyID);
        strcat(PC_base64, separator);
        strcat(PC_base64, pubkey);
        strcat(PC_base64, separator);
        strcat(PC_base64, ts);
        strcat(PC_base64, separator);
        strcat(PC_base64, te);
        strcat(PC_base64, separator);
        strcat(PC_base64, cert_sig);
        strcat(PC_base64, separator);
        /* Decode mesage */
        int message_decode_len = 0;
        int message_sig_decode_len = 0;
        int KeyID_decode_len = 0;
        int pubkey_decode_len = 0;
        int ts_decode_len = 0;
        int te_decode_len = 0;
        int cert_sig_decode_len = 0;
        unsigned char message_decode[1024] = {'\0'};
        unsigned char message_sig_decode[1024] = {'\0'};
        unsigned char KeyID_decode[1024] = {'\0'};
        unsigned char pubkey_decode[1024] = {'\0'};
        unsigned char ts_decode[1024] = {'\0'};
        unsigned char te_decode[1024] = {'\0'};
        unsigned char cert_sig_decode[1024] = {'\0'};
        strcpy(message_decode, message);
        message_decode_len = strlen(message);
        message_sig_decode_len = base64_decode(message_sig, strlen(message_sig), message_sig_decode);
        KeyID_decode_len = base64_decode(KeyID, strlen(KeyID), KeyID_decode);
        pubkey_decode_len = base64_decode(pubkey, strlen(pubkey), pubkey_decode);
        strcpy(ts_decode, ts);
        ts_decode_len = strlen(ts_decode);
        strcpy(te_decode, te);
        te_decode_len = strlen(te_decode);
        cert_sig_decode_len = base64_decode(cert_sig, strlen(cert_sig), cert_sig_decode);
        printf("Received message is:\n%s\n", message_decode);
        link_list* temp=p;
        int doespcstore = 0;
        int times = 1;
        while (temp->next) {
                temp=temp->next;
                strcpy(PC_store,temp->str);
                int key_num;
                for(key_num=0;key_num<7;key_num++)
                {
                        PC_store_KeyID[key_num]=PC_store[key_num];
                }
                for(key_num=0;key_num<7;key_num++)
                {
                        PC_received_KeyID[key_num]=KeyID[key_num];
                }
                if(!strcmp(PC_store_KeyID, PC_received_KeyID) == 0)
                {
                        times = times + 1;
                }
                else{
                        doespcstore = times;
                }
        }
        if (doespcstore == 0)                             // If PCSave is not same as PC receive
        {/* Verify Signatuer, if correct save as PCSave */
                /* Get system time */
                struct timespec time_now;
                clock_gettime(CLOCK_REALTIME, &time_now);
                time_t t = time_now.tv_sec;     // Get current time from 1970-01-01, count on seconds
                int t_current = time(&t) / 60;                              // start time, count on minutes
                int ts_int = atoi(ts);
                int te_int = atoi(te);
                if((t_current < ts_int) || (t_current > te_int))            // Check if certificate is valid
                {
                        printf("Certificate expired.\n");
                        return 0;
                }
                /* Construct pseudonym for verify */
                int pseudonym_len;
                pseudonym_len = KeyID_decode_len + ts_decode_len + te_decode_len + pubkey_decode_len;
                unsigned char pseudonym[pseudonym_len];
                for(i = 0; i < 4; i++)
                {
                        pseudonym[i] = KeyID_decode[i];
                }
                for(i = 4, j = 0; j < ts_decode_len; i++, j++)
                {
                        pseudonym[i] = ts_decode[j];
                }
                for(i = 4 + ts_decode_len, j = 0; j < te_decode_len; i++, j++)
                {
                        pseudonym[i] = te_decode[j];
                }
                for(i = 4 + ts_decode_len + te_decode_len, j = 0; j < pubkey_decode_len; i++, j++)
                {
                        pseudonym[i] = pubkey_decode[j];
                }
                /* read CA's public key from CA certificate*/
                FILE *f = fopen("cacert.pem", "r");
                X509 *x_509 = PEM_read_X509(f, NULL, NULL, NULL);
                fclose(f);
                if (x_509 == NULL)
                {
                        printf("Error：PEM_read_X509()\n");
                        return 0;
                }
                EVP_PKEY *evp_pkey = X509_get_pubkey(x_509);
                if (evp_pkey == NULL)
                {
                        printf("Error：X509_get_pubkey()\n");
                        return 0;
                }
                EC_KEY *cert_ec_key = EVP_PKEY_get1_EC_KEY(evp_pkey);
                if (cert_ec_key == NULL)
                {
                        printf("Error：EVP_PKEY_get1_EC_KEY()\n");
                        return 0;
                }
                /* Verify PC signature */
                int PCresult;
                PCresult = verify(cert_ec_key, cert_sig_decode, cert_sig_decode_len, pseudonym);
                switch (PCresult)
                {
                case 0:
                        printf("Pseudonym Certificate Signature Invalid.\n");                              // Return 0 if verification failed
                        return 0;
                        break;
                case -1:
                        printf("Pseudonym Certificate Signature Verification Error.\n");
                        return 0;
                        break;
                case 1:
                        printf("Pseudonym Certificate Signature Verification Successful.\n");                 // Keep running if verification success
                        link_list * temp_insert=(link_list*)malloc(sizeof(link_list));
                        link_list * temp_locate=p;
                        while (temp_locate->next) {
                                temp_locate=temp_locate->next;
                        }
                        //printf("PC_base64:%s\n",PC_base64);
                        char *msg_temp = (char *)malloc((strlen(PC_base64)+1)*1);
                        strcpy(msg_temp, PC_base64);
                        temp_insert->str = msg_temp;
                        temp_insert->next = NULL;
                        temp_locate->next = temp_insert;
                        break;
                default:
                        break;
                }
        }
        else        // Use PCSave to verify Beacon Signature
        {
                link_list* temp_pick=p;
                for(int i = 0; i<doespcstore; i++){
                        temp_pick=temp_pick->next;
                }
                /* Get PCSave message segment */
                /* Reset value of KeyID and pubkey, because they are the value of receive message */
                printf("Received PC already saved, then skip PC verification!\n");
                strcpy(KeyID, zero_buffer);
                strcpy(pubkey, zero_buffer);
                unsigned char PCSave[1024] = {'\0'};
                strcpy(PCSave,temp_pick->str);
                for(i = 0, j = 0; i < strlen(PCSave); i++, j++)
                {
                        if(PCSave[i] != '|')
                        {
                                KeyID[j] = PCSave[i];
                        }
                        else
                        {
                                i++;
                                break;
                        }
                }
                for(i, j = 0; i < strlen(PCSave); i++, j++)
                {
                        if(PCSave[i] != '|')
                        {
                                pubkey[j] = PCSave[i];
                        }
                        else
                        {
                                i++;
                                break;
                        }
                }
                strcpy(pubkey_decode, zero_buffer);
                //int pubkey_decode_len = 0;
                pubkey_decode_len = base64_decode(pubkey, strlen(pubkey), pubkey_decode);
        }


        /* Write public key into EC_key format */
        EC_KEY *ec_key;
        EC_GROUP *ec_group;
        unsigned char *pp = pubkey_decode;
        if ((ec_key = EC_KEY_new()) == NULL)
        {
                printf("Error：EC_KEY_new()\n");
                return 0;
        }
        if ((ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) == NULL)
        {
                printf("Error：EC_GROUP_new_by_curve_name()\n");
                EC_KEY_free(ec_key);
                return 0;
        }

        int ret = EC_KEY_set_group(ec_key, ec_group);
        if (ret != 1)
        {
                printf("Error：EC_KEY_set_group\n");
                EC_KEY_free(ec_key);
                return 0;
        }
//    ec_key = o2i_ECPublicKey(&ec_key, (const unsigned char **)&pp, strlen(pubkey_decode));
        ec_key = o2i_ECPublicKey(&ec_key, (const unsigned char **)&pp, pubkey_decode_len);
        if (ec_key == NULL)
        {
                printf("Error：o2i_ECPublicKey\n");
                EC_KEY_free(ec_key);
                return 0;
        }
        /* Verify beacon message */
        int Beacon_result;
        Beacon_result = verify(ec_key, message_sig_decode, message_sig_decode_len, message_decode);
        switch (Beacon_result)
        {
        case 0:
                printf("Beacon Signature Invalid.\n");
                return 0;
                break;
        case -1:
                printf("Beacon Signature Verification Error.\n");
                return 0;
                break;
        case 1:
                printf("Beacon Verification Success.\n");
                break;
        default:
                break;
        }
        return 1;
}

/*****************************************************************************
 * Function Name: base64_decode
 * Description: Decode message in Base64 format, the encode message ended with '|'
 * @ in_str:  Input string
 * @ in_len:  Input string length
 * @ out_str: Decode message buffer
 *
 * Return
 * @ size: Decode message length
 * @ 0: Function Error
*/

int base64_decode(char in_str[], int in_len, char out_str[])
{
        BIO *b64, *bio;
        BUF_MEM *bptr = NULL;
        int counts;
        int size = 0;
        if (in_str == NULL || out_str == NULL)
                return -1;
        b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

        bio = BIO_new_mem_buf(in_str, in_len);
        bio = BIO_push(b64, bio);

        size = BIO_read(bio, out_str, in_len);
        out_str[size] = '\0';

        BIO_free_all(bio);
        return size;
}

/*****************************************************************************
 * Function Name: SignMain
 * Description: Main function for signatuer
 *
 * Parameter
 * @ ec_key:    Private key for verify
 * @ sig:       Signature storage buffer
 * @ siglen:    Signature length
 * @ message: Message used for signature
 *
 * Return
 * @ 1: Function success
 * @ 0: Function error
*/

int verify(EC_KEY *ec_key, const unsigned char *sig, int siglen, unsigned char message[])
{

        int ret;
        unsigned char digest[32]={};
        unsigned int digest_len = 0;

        if(!EVP(message, digest, &digest_len))
        {
                printf("Error：EVP\n");
                return 0;
        }

        /* verify the signature signed by CA's private key */
        ret = ECDSA_verify(0, digest, digest_len, sig, siglen, ec_key);
        return ret;
}
