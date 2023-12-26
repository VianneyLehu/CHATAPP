#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <fcntl.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <gtk/gtk.h>


#define CONNECTION_PORT 3500

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
char new_message[1024];
char recipient[20] = "";
char buff[1024];

SSL_CTX *ctx;
SSL *ssl;

GtkWidget *scrolled_window; // Declare scrolled_window globally


SSL_CTX *InitCTX(void) {
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

void ShowCerts(SSL *ssl) {
    char *line;
    X509 *cert;
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
    } else {
        printf("Info: No client certificates configured.\n");
    }
}

void send_message(const char *message) {
    int res = SSL_write(ssl, message, strlen(message));
    if (res <= 0) {
        printf("Error sending message.\n");
    }
}

void add_text_to_scrolled_window(GtkWidget *scrolled_window, const gchar *text) {


    GtkWidget *text_view = gtk_bin_get_child(GTK_BIN(scrolled_window)); // Get the child (text view) of the scrolled window

    GtkTextBuffer *buffer;
    GtkTextIter iter;

    if (GTK_IS_TEXT_VIEW(text_view)) {
        buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_view));
        gtk_text_buffer_get_end_iter(buffer, &iter);
        gtk_text_buffer_insert(buffer, &iter, text, -1);
    } else {
        g_warning("Child of scrolled window is not a text view.");
    }
}

// Callback function when the "Send" button is clicked
void on_send_button_clicked(GtkButton *button, gpointer user_data) {
    GtkEntry *entry = GTK_ENTRY(user_data);
    const gchar *text = gtk_entry_get_text(entry);
    send_message(text);
    // Get access to the scrolled window
    GtkWidget *scrolled_window = g_object_get_data(G_OBJECT(button), "scrolled_window");

    // Add the entered text to the scrolled window
    add_text_to_scrolled_window(scrolled_window, "You:");
    add_text_to_scrolled_window(scrolled_window, text);
    add_text_to_scrolled_window(scrolled_window,"\n");
    gtk_entry_set_text(entry, ""); // Clear the entry after sending
}


gboolean update_scrolled_window(gpointer data) {
    const char *received_text = (const char *)data;
    printf("test: %s\n", received_text);
    add_text_to_scrolled_window(scrolled_window, ">");
    add_text_to_scrolled_window(scrolled_window, received_text);
    add_text_to_scrolled_window(scrolled_window, "\n");


    return G_SOURCE_REMOVE; // Remove the idle function after executing it once
}

void handle_request(char* username){
    gtk_init(NULL, NULL); // Initialize GTK
    GtkWidget *dialog;
    dialog = gtk_message_dialog_new(NULL,
                                    GTK_DIALOG_MODAL,
                                    GTK_MESSAGE_QUESTION,
                                    GTK_BUTTONS_YES_NO,
                                    "Accept conversation request from %s", username);

    gint result = gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);

    if (result == GTK_RESPONSE_YES) {
        char answer[strlen("/accept ")+strlen(username)+1];
        sprintf(answer, "/accept %s", username);
        send_message(answer);
    } 
    else{
        char answer2[strlen("/refuse ")+strlen(username)+1];
        sprintf(answer2, "/refuse %s", username);
        send_message(answer2);
    }
}



void *receive_messages(void *arg) {
    pthread_detach(pthread_self());
    int socket_send = *(int *)arg; 


    while (1) {
        pthread_mutex_lock(&mutex);
        memset(buff, 0, 1024);
        pthread_mutex_unlock(&mutex);

        ssize_t res = SSL_read(ssl, buff, sizeof(buff));

        if (res <= 0) {
            printf("Server disconnected\n");
            break;
        }

        if(strncmp(buff, "/request", 8) == 0) {
            char *usertmp = strstr(buff, " ");
            char *username = usertmp + 1;

            printf("test:%s\n",username);
            handle_request(username);
        }else{
            g_idle_add(update_scrolled_window, g_strdup(buff));
        }

    }

    pthread_exit(NULL);
}

int main(int argc, char **argv) {


    SSL_library_init();
    ctx = InitCTX();

    gtk_init(&argc, &argv);

    // Create main window
    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_default_size(GTK_WINDOW(window), 400, 300);
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    // Create a text view
    GtkWidget *text_view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(text_view), FALSE);

    // Create a scrolled window and set the text view as its child
    scrolled_window = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window),
                                GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(scrolled_window), text_view);

    // Create entry for user input
    GtkWidget *entry = gtk_entry_new();
    gtk_entry_set_max_length(GTK_ENTRY(entry), 1024); // Set maximum length of input
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry), "Type your message here...");

    // Create "Send" button
    GtkWidget *send_button = gtk_button_new_with_label("Send");

    // Box for organizing entry and send button horizontally
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_box_pack_start(GTK_BOX(box), entry, TRUE, TRUE, 5);
    gtk_box_pack_start(GTK_BOX(box), send_button, FALSE, FALSE, 5);

    // Vertical box for organizing scrolled window, box, and other widgets
    GtkWidget *main_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_box_pack_start(GTK_BOX(main_box), scrolled_window, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(main_box), box, FALSE, FALSE, 0);
    gtk_container_add(GTK_CONTAINER(window), main_box);

    // Connect the "Send" button clicked signal to the callback function
    g_signal_connect(send_button, "clicked", G_CALLBACK(on_send_button_clicked), entry);
    g_object_set_data(G_OBJECT(send_button), "scrolled_window", scrolled_window);

    int socketClient = socket(AF_INET, SOCK_STREAM, 0);
    if (socketClient == -1) {
        printf("FAIL TO CREATE A SOCKET:\n");
        printf("ERRNO [%i] : %s \n", errno, strerror(errno));
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in addrClient;
    addrClient.sin_addr.s_addr = inet_addr("127.0.0.1");
    addrClient.sin_family = AF_INET;
    addrClient.sin_port = htons(CONNECTION_PORT);

    if (connect(socketClient, (const struct sockaddr *)&addrClient, sizeof(addrClient)) == -1) {
        printf("FAIL TO CONNECT :\n");
        printf("ERRNO [%i] : %s \n", errno, strerror(errno));
        exit(EXIT_FAILURE);
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, socketClient);

    if (SSL_connect(ssl) == -1) {
        ERR_print_errors_fp(stderr);
    }

    ShowCerts(ssl);

    char rcv[1024];
    char username[20];
    memset(rcv, 0, sizeof(rcv));

    int len = SSL_read(ssl, rcv, sizeof(rcv));
    if (len == -1 && errno != EAGAIN) {
        printf("ERRNO [%i] : %s \n", errno, strerror(errno));
        exit(EXIT_FAILURE);
    }

    printf("%s", rcv);
    fflush(stdout);

    if (fgets(username, sizeof(username), stdin) == NULL) {
        printf("ERRNO [%i] : %s \n", errno, strerror(errno));
        exit(EXIT_FAILURE);
    }

    int res = SSL_write(ssl,username, strlen(username)-1);
    if (res <= 0) {
        printf("Error sending message.\n");
    }

    gtk_window_set_title(GTK_WINDOW(window),username);


    pthread_t receive_thread;

    pthread_create(&receive_thread, NULL, receive_messages, (void *)&socketClient);


    gtk_widget_show_all(window);

    gtk_main();

    close(socketClient);
    SSL_CTX_free(ctx);

    return 0;
}
