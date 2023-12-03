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

    #define CONNECTION_PORT 3500

    #define MAX_CLIENTS 10


    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;


    int client_count = 0;


    struct client{
        char name[20];
        int socket;
        int in_conversation_with;
    };



    struct client clients[MAX_CLIENTS];


    void send_message(int socket, const char *message) {

        printf("test1\n");

        send(socket, message, strlen(message), 0);
    }


    void broadcast_message(char* message, int socket_sender){

        for (int i = 0; i <= client_count; i++) {

            if(clients[i].in_conversation_with != -1 && clients[i].in_conversation_with != socket_sender){
                send_message(clients[i].in_conversation_with, message);
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


        int socket = *(int *)arg;


        char *msg = "To register provide a username:";

        char username[20];


        if(send(socket,msg,strlen(msg), 0) == -1){
            printf("ERRNO [%i] : %s \n", errno, strerror(errno));
            exit(EXIT_FAILURE);
        }



        int len = recv(socket, username, sizeof(username), 0);

        
        if(len == -1 && errno != EAGAIN){
            printf("ERRNO [%i] : %s \n", errno, strerror(errno));
            exit(EXIT_FAILURE);
        }


        pthread_mutex_lock(&mutex);

        memcpy(clients[client_count].name, username, strlen(username));

        pthread_mutex_unlock(&mutex);

        printf("\n%s", username);

        pthread_mutex_lock(&mutex);

        clients[client_count].in_conversation_with = -1;
        clients[client_count].socket = socket;

        printf("\n name : %s \n socket : %d \nin conv: %d\n",clients[client_count].name, clients[client_count].socket, clients[client_count].in_conversation_with);

        client_count ++;


        pthread_mutex_unlock(&mutex);

        char buff[1024];


        while (1) {

            memset(buff,0,1024);

            int len = recv(socket,buff,sizeof(buff), 0);
    
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

            broadcast_message(buff, socket);

            printf("test\n");



        }


        close(socket);

        pthread_exit(NULL);

    }



    int main(){


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

        printf("close \n");

        return 0;

    }
