#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <tommath.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <pthread.h>
#include "aes.c"

#define SERVER_PORT 10000   // 服务器端口
#define QUEUE_SIZE    10        // 连接数
#define BUFFER_SIZE 1024    // 缓冲区

typedef struct aes_arg
{
    int sockfd;
    struct sockaddr_in client_addr;
    // mp_int aes_key;
    unsigned char aes_iv[32];
    unsigned char aes_tag[16];
    unsigned char aes_key[32];
} aes_arg;

void recv_message(aes_arg *arg)
{
    int sock = arg->sockfd;
    struct sockaddr_in client_addr = arg->client_addr;
    char recv_buffer[512] = {0};
    int recv_n = 0;
    // 接收数据
    while (1)
    {
        recv_n = recv(sock, recv_buffer, 512, 0);
        if (recv_n < 0)    // 接收出错
        {
            printf("客户端 %s:%d 接收消息错误\n", inet_ntoa(client_addr.sin_addr), client_addr.sin_port);
            perror("error: ");
            close(arg->sockfd);
            return;
        }
        else if (recv_n == 0)    //连接关闭
        {
            printf("客户端 %s:%d 连接关闭\n", inet_ntoa(client_addr.sin_addr), client_addr.sin_port);
            close(arg->sockfd);
            return;
        }

        // printf("recv_n: %d\n", recv_n);
        recv_buffer[recv_n] = '\0';
        unsigned int iv_len = 32;
        unsigned int tag_len = 16;
        // unsigned int ct_len=recv_n-iv_len;
        unsigned int ct_len = recv_n - iv_len - tag_len;
        unsigned char plain_text[256] = {0};
        // unsigned char cipher_text[256+tag_len]={0};
        unsigned char cipher_text[256] = {0};
        unsigned char tag[16] = {0};
        unsigned char iv[32] = {0};

        memcpy(iv, recv_buffer, iv_len);
        memcpy(cipher_text, recv_buffer + iv_len, ct_len);
        memcpy(tag, recv_buffer + recv_n - tag_len, tag_len);
        cipher_text[ct_len] = '\0';
        printf("\n来自客户端 %s:%d的消息:\n", inet_ntoa(client_addr.sin_addr), client_addr.sin_port);
        BIO_dump_fp(stdout, recv_buffer, recv_n);
        printf("\niv:\n");
        BIO_dump_fp(stdout, iv, iv_len);
        printf("\ntag:\n");
        BIO_dump_fp(stdout, tag, tag_len);
        printf("\ncipher_text:\n");
        BIO_dump_fp(stdout, cipher_text, ct_len);
        printf("\nkey:\n");
        BIO_dump_fp(stdout, arg->aes_key, 32);
        decrypt(arg->aes_key, plain_text, ct_len, cipher_text, iv, iv_len, tag, tag_len);
        printf("\nplain_text:\n");
        BIO_dump_fp(stdout, plain_text, ct_len);
        printf("\n----------------------------------------------\n");
    }
}
