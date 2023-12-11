#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <stdbool.h>
#include "openssl/ssl.h"
#include "openssl/err.h"


#define CONNECTION_PORT 3500


pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;


char recipient[20] = ""; 

char buff[1024];

SSL_CTX *ctx;

SSL *ssl;





SSL_CTX* InitCTX(void) {

    SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();

    SSL_load_error_strings();

    method = (SSL_METHOD *)TLS_client_method();

    ctx = SSL_CTX_new(method);

    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    return ctx;
}

void ShowCerts(SSL* ssl) {

    char *line;
    X509 *cert;
    
    // get the server's certificate
    cert = SSL_get_peer_certificate(ssl);
    
    if (cert != NULL) {

        printf("Server certificates:\n");

        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);

        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);

        X509_free(cert);
    }
    else
        printf("Info: No client certificates configured.\n");
}



void send_message(int socket, const char * message) {

    if(SSL_accept(ssl) != -1){
        SSL_write(ssl, message, strlen(message));
    }else{
        SSL_write(ssl, "SSL error", strlen("SSL error"));
    }

}




void *receive_messages(void *arg) {

    pthread_detach(pthread_self());


    int socket_send = *(int *)arg;

    while (1) {

        pthread_mutex_lock(&mutex);
        memset(buff, 0,1024);
        pthread_mutex_unlock(&mutex);

        ssize_t res = SSL_read(ssl, buff, sizeof(buff));
        
        if (res <= 0) {
            printf("Server disconnected\n");
            break;
        }

        buff[res] = '\0';

        int i =0;
        
        printf("\n#%s\n", buff);
    }

    pthread_exit(NULL);
}



int main()

{

    SSL_library_init();

    ctx = InitCTX();


    
    int socketClient = socket(AF_INET, SOCK_STREAM, 0);

    if(socketClient == -1){
        printf("FAIL TO CREATE A SOCKET:\n");
        printf("ERRNO [%i] : %s \n", errno, strerror(errno));

        exit(EXIT_FAILURE);
    }

    struct sockaddr_in addrClient; 
    addrClient.sin_addr.s_addr = inet_addr("127.0.0.1");
    addrClient.sin_family = AF_INET;
    addrClient.sin_port = htons(CONNECTION_PORT);

    if(connect(socketClient, (const struct sockaddr*) &addrClient, sizeof(addrClient)) == -1){
        printf("FAIL TO CONNECT :\n");
        printf("ERRNO [%i] : %s \n", errno, strerror(errno));
        exit(EXIT_FAILURE);
    } 


    ssl = SSL_new(ctx);

    SSL_set_fd(ssl, socketClient);

    if (SSL_connect(ssl) == -1){
        ERR_print_errors_fp(stderr);
    }

    ShowCerts(ssl);


    printf("socket : %d", socketClient);

    printf("Connected\n");


    char rcv[1024];

    char username[20];

    memset(rcv, 0, sizeof(rcv));

    
    int len = SSL_read(ssl, rcv, sizeof(rcv));

    if(len == -1 && errno != EAGAIN){
        printf("ERRNO [%i] : %s \n", errno, strerror(errno));
        exit(EXIT_FAILURE);
    }

    printf("%s", rcv);

    fflush(stdout);

    if(fgets(username, sizeof(username), stdin) == NULL){
        printf("ERRNO [%i] : %s \n", errno, strerror(errno));
        exit(EXIT_FAILURE);

    } 


    send_message(socketClient, username);




    pthread_t receive_thread;


    char inputMsg[1024];


    pthread_create(&receive_thread, NULL, receive_messages, (void *)&socketClient);


    while(1){

        printf("\n>");

        fflush(stdout);
        
        memset(inputMsg, 0, sizeof(inputMsg));

        if(fgets(inputMsg, sizeof(inputMsg), stdin) == NULL){
            printf("ERRNO [%i] : %s \n", errno, strerror(errno));
            exit(EXIT_FAILURE);
        }

        pthread_mutex_lock(&mutex);

        send_message(socketClient, inputMsg);


        pthread_mutex_unlock(&mutex);
        
        if (memcmp(inputMsg, "/stop", 5) == 0) {
            //faire qqchose

        }

    
        if (memcmp(inputMsg, "/exit", 5) == 0) {
            printf("Closing connection\n");

            SSL_free(ssl);

            break;
        }


    }


    
    close(socketClient);

    SSL_CTX_free(ctx);



    return 0;
}