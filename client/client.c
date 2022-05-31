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
