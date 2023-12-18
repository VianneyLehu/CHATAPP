# CHATAPP
Chat app using socket and encrypt data with openssl lib which use TLS security protocol.
Compile: 
gcc -o client client.c ssl_functions.c -lssl -lcrypto -lpthread
gcc -o server server.c ssl_functions.c -lssl -lcrypto -lpthread

