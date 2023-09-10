#include "functions.c"


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>

int main() {
    int raw_s;
    raw_s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_s < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Specify the network interface you want to capture packets from
    struct sockaddr_ll saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sll_family = AF_PACKET;
    saddr.sll_protocol = htons(ETH_P_ALL);
    saddr.sll_ifindex = if_nametoindex("eth0"); // Replace "eth0" with your interface name

    if (bind(raw_s, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
        perror("bind");
        close(raw_s);
        exit(EXIT_FAILURE);
    }

    // int t = 1000;
    while (1) {
        unsigned char *packet = (unsigned char *)malloc(65536);
        int n_pac = recvfrom(raw_s, packet, 65536, 0, NULL, NULL);
        if (n_pac == 0) {
            break;
            return 0;
        }
        else if(n_pac < 0){
            perror("recvfrom");
            close(raw_s);
            exit(EXIT_FAILURE);
            return 0;
        }

        // question 1 - 
        // (a) run this function
        packet_information(packet, n_pac); 
        
        free(packet);
    }

    close(raw_s); // Close the socket when you're done with it
    return 0;
}