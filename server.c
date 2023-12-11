    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <fcntl.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <unistd.h>
    #include <string.h> 
    #include <stdlib.h>
    #include <stdbool.h>
    #include <pthread.h>
    #include <errno.h>
    
    #include "openssl/ssl.h"
    #include "openssl/err.h"

    #define CONNECTION_PORT 3500

    #define MAX_CLIENTS 10


    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;


    SSL_CTX *ctx;



    int client_count = 0;


    struct client{
        char name[20];
        SSL *ssl;
        int socket;
        int in_conversation_with;
    };



    struct client clients[MAX_CLIENTS];




    SSL_CTX* InitServerCTX(void)
    {
        SSL_METHOD *method;
        SSL_CTX *ctx;

        // load & register all cryptos, etc.
        OpenSSL_add_all_algorithms();
        
        // load all error messages
        SSL_load_error_strings();

        // create new server-method instance
        method = (SSL_METHOD *)TLS_server_method();

        // create new context from method
        ctx = SSL_CTX_new(method);

        if (ctx == NULL) {
            ERR_print_errors_fp(stderr);
            abort();
        }

        return ctx;
    }

    void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile) {

        // set the local certificate from CertFile
        if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors_fp(stderr);
            abort();
        }

        // set the private key from KeyFile (may be the same as CertFile)
        if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors_fp(stderr);
            abort();
        }

        // verify private key
        if (!SSL_CTX_check_private_key(ctx)) {
            fprintf(stderr, "Private key and public certificate do not match.\n");
            abort();
        }
    }

    void ShowCerts(SSL* ssl) {

        char *line;
        X509 *cert;

        // get certificates (if available)
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
            printf("No certificates.\n");
    }




    void send_message(SSL *ssl, const char * message) {
        if(SSL_connect(ssl) == -1){
            ERR_print_errors_fp(stderr);
        }else{
            SSL_write(ssl, message, strlen(message));
        }
    }



    void broadcast_message(char* message, int socket_sender){

       
        for (int i = 0; i < client_count; i++) {
            if (clients[i].in_conversation_with != -1 && clients[i].in_conversation_with != socket_sender) {
                for(int j=0;j<client_count;j++){
                    if(clients[i].in_conversation_with == clients[j].socket){
                        send_message(clients[j].ssl, message);
                    }
                }
            }
        }
    }



    void check_msg(char* buff, int sender_socket){

        
        if((strstr(buff, "/msg")) != NULL){
            
            char *usertemp = strstr(buff, " ");
            int receiver = -1; 


            if (usertemp != NULL) {
                char* username = usertemp + 1;

                pthread_mutex_lock(&mutex);

                for (int i = 0; i <= client_count; i++) {

                    if (strcmp(clients[i].name,username) == 0) {
                        clients[i].in_conversation_with = sender_socket;
                        receiver = clients[i].socket;
                        break; 
                    }
                }

                printf("receiver : %d\n", receiver);

                for(int i=0; i<=client_count;i++){
                    if(clients[i].socket == sender_socket){
                        clients[i].in_conversation_with = receiver;
                    }   
                }

                pthread_mutex_unlock(&mutex);

            }

        }




    }


    void *client_handler(void *arg){


        pthread_detach(pthread_self());



        SSL *ssl = SSL_new(ctx);


        int socket = *(int *)arg;

        pthread_mutex_lock(&mutex);


        SSL_set_fd(ssl,socket);

        clients[client_count].ssl = ssl;
        clients[client_count].in_conversation_with = -1;
        clients[client_count].socket = socket;

        if(SSL_accept(ssl)==-1){
            ERR_print_errors_fp(stderr);    
            exit(EXIT_FAILURE);
        }


        ShowCerts(ssl);


        pthread_mutex_unlock(&mutex);



        char *msg = "To register provide a username:";

        char username[20];


        send_message(ssl,msg);
        

        int len = SSL_read(ssl, username, sizeof(username));

        
        if(len == -1 && errno != EAGAIN){
            printf("ERRNO [%i] : %s \n", errno, strerror(errno));
            exit(EXIT_FAILURE);
        }


        pthread_mutex_lock(&mutex);

        memcpy(clients[client_count].name, username, strlen(username));

        printf("\n name : %s \n socket : %d \nin conv: %d\n",clients[client_count].name, clients[client_count].socket, clients[client_count].in_conversation_with);


        client_count++;

        pthread_mutex_unlock(&mutex);



        char buff[1024];

        while (1) {

            memset(buff,0,1024);

            int len = SSL_read(ssl, buff, sizeof(buff));
    
            if(len == -1 && errno != EAGAIN){
                printf("ERRNO [%i] : %s \n", errno, strerror(errno));
                exit(EXIT_FAILURE);
            }


            printf("%s\n", buff);



            if (len <= 0) {
                printf("Client disconnected.\n");
                break;
            }


            check_msg(buff, socket);


            broadcast_message(buff,socket);



        }


        close(socket);

        pthread_exit(NULL);

    }



    int main(){



        SSL_library_init();

        ctx = InitServerCTX();

        LoadCertificates(ctx, "mycert.pem", "mycert.pem");


        pthread_mutex_init(&mutex, NULL); 

        int socketClient[MAX_CLIENTS];

        int count = 0;

        int socketServer = socket(AF_INET, SOCK_STREAM, 0);

        struct sockaddr_in addrServ; 
        addrServ.sin_addr.s_addr = inet_addr("127.0.0.1");
        addrServ.sin_family = AF_INET; 
        addrServ.sin_port = htons(CONNECTION_PORT);



        if(bind(socketServer, (const struct sockaddr*) &addrServ, sizeof(addrServ)) != 0){
            printf("ERRNO [%i] : %s \n", errno, strerror(errno));
            exit(EXIT_FAILURE);
        }

        printf("bind : %d\n ", socketServer);

        if(listen(socketServer,MAX_CLIENTS) != 0){
            printf("ERRNO [%i] : %s \n", errno, strerror(errno));
            exit(EXIT_FAILURE);
        }

        printf("listen\n");


        pthread_t threads[MAX_CLIENTS];
        struct sockaddr_in addrClient; 
        socklen_t csize = sizeof(addrClient);

        while(1){

            if((socketClient[count] = accept(socketServer, (struct sockaddr*) &addrClient, &csize)) == -1){
                printf("ERRNO [%i] : %s \n", errno, strerror(errno));
                exit(EXIT_FAILURE);
            }

            if (client_count >= MAX_CLIENTS) {
                close(socketServer);
                printf("Too many connexions \n");
                exit(-1);
            }else{
                printf("New client online \n");
            }



            pthread_create(&threads[count], NULL, client_handler,(void*)&socketClient[count]);

            count ++;

        }



        pthread_mutex_destroy(&mutex); 

        close(socketServer);

        SSL_CTX_free(ctx);

        printf("close \n");

        return 0;

    }
