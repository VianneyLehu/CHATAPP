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
#define CONNECTION_PORT 3500


pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;


char recipient[20] = ""; 

char buff[1024];



void *receive_messages(void *arg) {

    pthread_detach(pthread_self());


    int socket_send = *(int *)arg;

    while (1) {

        pthread_mutex_lock(&mutex);
        memset(buff, 0,1024);
        pthread_mutex_unlock(&mutex);

        ssize_t res = recv(socket_send, buff, sizeof(buff) - 1, 0);
        
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


    printf("socket : %d", socketClient);

    printf("Connected\n");


    char rcv[1024];

    char username[20];

    
    int len = recv(socketClient, rcv, sizeof(rcv), 0);

    if(len == -1 && errno != EAGAIN){
        printf("ERRNO [%i] : %s \n", errno, strerror(errno));
        exit(EXIT_FAILURE);
    }

    printf("\n%s", rcv);

    fflush(stdout);

    if(fgets(username, sizeof(username), stdin) == NULL){
        printf("ERRNO [%i] : %s \n", errno, strerror(errno));
        exit(EXIT_FAILURE);

    } 


    if(send(socketClient, username, strlen(username), 0) == -1){
        printf("ERRNO [%i] : %s \n", errno, strerror(errno));
        exit(EXIT_FAILURE);
    }


    pthread_t receive_thread;


    char inputMsg[1024];


    pthread_create(&receive_thread, NULL, receive_messages, (void *)&socketClient);


    while(1){

        printf("\n> ");

        fflush(stdout);
        
        memset(inputMsg, 0, sizeof(inputMsg));

        if(fgets(inputMsg, sizeof(inputMsg), stdin) == NULL){
            printf("ERRNO [%i] : %s \n", errno, strerror(errno));
            exit(EXIT_FAILURE);
        }

        pthread_mutex_lock(&mutex);
        if(send(socketClient,inputMsg, strlen(inputMsg), 0) == -1){
            printf("ERRNO [%i] : %s \n", errno, strerror(errno));
            exit(EXIT_FAILURE);
        }

        pthread_mutex_unlock(&mutex);
        
        if (memcmp(inputMsg, "/stop", 5) == 0) {
            //faire qqchose

        }

    
        if (memcmp(inputMsg, "/exit", 5) == 0) {
            printf("Closing connection\n");
            break;
        }


    }


    
    close(socketClient);



    return 0;
}