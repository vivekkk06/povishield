#include <arpa/inet.h>
#include <stdio.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
int main(void) {
    int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (s >= 0) { puts("ESCAPED: raw socket"); return 0; }
    return 1;
}
