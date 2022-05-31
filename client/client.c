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

#define SERVER_PORT 10000   // 服务器端口
#define QUEUE_SIZE    10        // 连接数
#define BUFFER_SIZE 1024    // 缓冲区
typedef struct aes_arg
{
    int sockfd;
    // mp_int aes_key;
    unsigned char aes_iv[32];
    unsigned char aes_tag[16];
    unsigned char aes_key[32];
} aes_arg;

// 生成长度为num的随机字符串
void generate_rand_str(unsigned char *str, int num)
{
    int i = 0;
    for (i = 0; i < num; i++)
    {
        str[i] = (char) rand() % 256;
    }
}

// 找原根
void find_primitive_root(mp_int *p, mp_int *primitive_root)
{
    // 原根检测
    // 对于数p,求出p-1所有不同的质因子p1,p2…pm
    // 对于任何2<=a<=x-1,判定a是否为p的原根,只需要检验a^((x-1)/p1),a^((x-1)/p2) …a^((x-1)/pm)这m个数
    // 是否存在一个数mod x为1
    // 若存在,a不是x的原根,a否则就是x的原根
    // LTM_PRIME_SAFE保证(p-1)/2也是素数,即p-1只有两个质因子2和(p-1)/2

    // p1=2
    mp_int p1;
    mp_init(&p1);
    mp_init_set(&p1, 2);

    // p2=(p-1)/2
    mp_int p2;
    mp_init(&p2);
    mp_sub_d(p, 1, &p2);
    mp_div_2(&p2, &p2);

    mp_int temp;
    mp_init(&temp);
    // 寻找原根
    // a^((p-1)/2) mod p ?= 1
    // a^2 mod p ?= 1
    while (1)
    {
        mp_exptmod(primitive_root, &p1, p, &temp);    // temp = p_r^2 mod p
        if (mp_cmp_d(&temp, 1) != MP_EQ)
        {
            // 如果上面的结果不是1
            // 再计算 temp = p_r^((p-1)/2) mod p
            mp_exptmod(primitive_root, &p2, p, &temp);
            if (mp_cmp_d(&temp, 1) != MP_EQ)
            {
                // 如果这个结果也不是1则找到原根了
                break;
            }
        }
        mp_add_d(primitive_root, 1, primitive_root);    // +1继续
    }
    mp_clear_multi(&p1, &p2, &temp, NULL);    // 释放
}

// 生成客户端密钥
void generate_client_key(int sockfd, unsigned char *aes_key)
{
    /*-------------------------------------*/
    // 生成p、g、b、y并发送p、g、y
    mp_int p;    // p
    mp_init(&p);    // 初始化mp_int结构使之可以安全的被库中其他函数使用
    mp_int primitive_root;    // 原根
    mp_init(&primitive_root);
    mp_set(&primitive_root, 2);
    generate_p(sockfd, &p, &primitive_root);    // 生成素数p、找到原根g并发送给客户端

    mp_int b;    // 客户端的私钥b
    mp_init(&b);
    mp_rand(&b, p.used);
    mp_int y;    // 客户端的公钥y
    mp_init(&y);
    mp_exptmod(&primitive_root, &b, &p, &y);    // y=g^b mod p

    char buffer[BUFFER_SIZE];
    mp_toradix(&y, buffer, 10);
    send(sockfd, buffer, strlen(buffer) + 1, 0);    // 发送y

    /*-----------------------------------*/
    // 接收服务器的x,key=x^b mod p
    recv(sockfd, buffer, BUFFER_SIZE, 0);
    mp_int x;
    mp_init(&x);
    mp_read_radix(&x, buffer, 10);
    mp_int key;
    mp_init(&key);
    mp_exptmod(&x, &b, &p, &key);
    mp_toradix(&key, buffer, 16);
    // printf("\nkey: \n%s\n", buffer);
    // 填充aes_key
    int i = 0;
    for (i = 0; i < 64; ++i)
    {
        if (buffer[i] >= 'A' && buffer[i] <= 'F')
            buffer[i] = buffer[i] - 55;    // 10-16
        if (buffer[i] >= '1' && buffer[i] <= '9')
            buffer[i] = buffer[i] - 48;    // 0-9
    }
    for (i = 0; i < 32; ++i)    // 十六进制 0xXX
        aes_key[i] = buffer[2 * i] * 16 + buffer[2 * i + 1];
}