server.exe: server.c 
    gcc -o server server.c -Wall -Wextra -g -lssl -lcrypto -lpthread 


client.exe: client.c
    gcc -o client client.c -Wall -Wextra -g -lssl -lcrypto -lpthread 



clean:
    rm -f *.o *.exe
