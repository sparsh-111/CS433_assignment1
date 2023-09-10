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



void analyze_packet_milkshake(const unsigned char *packet, int packet_size) {
    
    struct ether_header *eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        // Extract IP information
        struct ip *ip_header = (struct ip *)(packet + ETHER_HDR_LEN);
        
        if( strcmp(inet_ntoa(ip_header->ip_src) ,"127.0.0.1")){
            if (packet_size >= (ETHER_HDR_LEN + (ip_header->ip_hl << 2) + sizeof(struct tcphdr))) {
                // Check if there's enough data for a TCP header
                struct tcphdr *tcp_header = (struct tcphdr *)(packet + ETHER_HDR_LEN + (ip_header->ip_hl << 2));
                char *tcp_data = (char *)(packet + ETHER_HDR_LEN + (ip_header->ip_hl << 2) + (tcp_header->th_off << 2));
                // Extract TCP information
                if (strstr(tcp_data, "milkshake") != NULL) {
                    printf("Packet from localhost requested a milkshake. Flavor found in packet data: %s\n", tcp_data);
                }
                // printf(tcp_data,"\n");
            }   
        }
    }
}


void check_sum(const unsigned char *packet, int packet_size){
    struct ether_header *eth_header = (struct ether_header *)packet;
    struct ip *ip_header = (struct ip *)(packet + ETHER_HDR_LEN);
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + ETHER_HDR_LEN + (ip_header->ip_hl << 2));
    if (ntohs(tcp_header->th_sum) == 0x0ac4) {
        printf("Found TCP checksum '0x0ac4' in a TCP packet.\n");
        char *tcp_data = (char *)(packet + ETHER_HDR_LEN + (ip_header->ip_hl << 2) + (tcp_header->th_off << 2));
        printf("packet data : ", tcp_data);
    }
}


//given ip address, need to get sum of port
void Find_port_sum(unsigned char *packet, int packet_size) {
    //if (packet_size < (ETHER_HDR_LEN + sizeof(struct ip))) {
        // Packet is too short to contain an IP header
        //return;
    //}

    struct ether_header *eth_header = (struct ether_header *)packet;

    // Extract Ethernet information
    // printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
    //        eth_header->ether_shost[0], eth_header->ether_shost[1],
    //        eth_header->ether_shost[2], eth_header->ether_shost[3],
    //        eth_header->ether_shost[4], eth_header->ether_shost[5]);
    // printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
    //        eth_header->ether_dhost[0], eth_header->ether_dhost[1],
    //        eth_header->ether_dhost[2], eth_header->ether_dhost[3],
    //        eth_header->ether_dhost[4], eth_header->ether_dhost[5]);

    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        // Extract IP information
        struct ip *ip_header = (struct ip *)(packet + ETHER_HDR_LEN);
        // printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
        // printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));

        if( strcmp(inet_ntoa(ip_header->ip_src) ,"131.144.126.118") ||  strcmp(inet_ntoa(ip_header->ip_dst), "131.144.126.118")){
            if (packet_size >= (ETHER_HDR_LEN + (ip_header->ip_hl << 2) + sizeof(struct tcphdr))) {
                // Check if there's enough data for a TCP header
                struct tcphdr *tcp_header = (struct tcphdr *)(packet + ETHER_HDR_LEN + (ip_header->ip_hl << 2));
                
                // Extract TCP information
                // printf("Source Port: %d\n", ntohs(tcp_header->th_sport));
                // printf("Destination Port: %d\n", ntohs(tcp_header->th_dport));
                int src = ntohs(tcp_header->th_sport);
                int des =  ntohs(tcp_header->th_dport); 
                int s = src + des;
                printf("%d",  s);
                printf("\n");
            }   
        }
    }
}





void extract_secret(const unsigned char *packet, int packet_size) {
    struct ether_header *eth_header = (struct ether_header *)packet;

    // Check if the packet is Ethernet II
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        // Extract IP header
        struct ip *ip_header = (struct ip *)(packet + ETHER_HDR_LEN);

        // Determine the IP protocol (TCP or UDP)
        if (ip_header->ip_p == IPPROTO_TCP) {
            // TCP packet
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + ETHER_HDR_LEN + (ip_header->ip_hl << 2));
            
            // Extract TCP data (packet payload)
            int tcp_data_length = packet_size - ETHER_HDR_LEN - (ip_header->ip_hl << 2) - (tcp_header->th_off << 2);
            if (tcp_data_length > 0) {
                char *tcp_data = (char *)(packet + ETHER_HDR_LEN + (ip_header->ip_hl << 2) + (tcp_header->th_off << 2));
                char *secret_keyword = "secret";
                
                // Search for the secret keyword in TCP data
                if (strstr(tcp_data, secret_keyword) != NULL) {
                    printf("Found 'My username is secret' in a TCP packet:\n");
                    printf("Packet Data:\n%s\n", tcp_data);
                    printf("\n");
                }
            }
        } else if (ip_header->ip_p == IPPROTO_UDP) {
            // UDP packet
            // Similar extraction logic as TCP for UDP packets if needed
        }
    }
}



void packet_flag_data(unsigned char *packet, int packet_size){
    struct ip *ip_header = (struct ip *)(packet + 14); // Skip Ethernet header
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl << 2)); // Skip IP header

    // Check for keywords or characteristics in the packet content
    char *packet_data = (char *)(packet + 14 + (ip_header->ip_hl << 2) + (tcp_header->th_off << 2));

    // Check for the keyword "Flag"
    if (strstr(packet_data, "I come from localhost, I requested a milkshake. Find my flavour.") != NULL) {
        printf("Found 'Flag' in a TCP packet:\n");
        printf("Packet Data:\n%s\n", packet_data);
        printf("\n");
    }

    
}

void packet_information(unsigned char *packet, int packet_size) {
    //if (packet_size < (ETHER_HDR_LEN + sizeof(struct ip))) {
        // Packet is too short to contain an IP header
        //return;
    //}

    struct ether_header *eth_header = (struct ether_header *)packet;

    // Extract Ethernet information
    printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_header->ether_shost[0], eth_header->ether_shost[1],
           eth_header->ether_shost[2], eth_header->ether_shost[3],
           eth_header->ether_shost[4], eth_header->ether_shost[5]);
    printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_header->ether_dhost[0], eth_header->ether_dhost[1],
           eth_header->ether_dhost[2], eth_header->ether_dhost[3],
           eth_header->ether_dhost[4], eth_header->ether_dhost[5]);

    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        // Extract IP information
        struct ip *ip_header = (struct ip *)(packet + ETHER_HDR_LEN);
        printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
        printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));

        if (packet_size >= (ETHER_HDR_LEN + (ip_header->ip_hl << 2) + sizeof(struct tcphdr))) {
            // Check if there's enough data for a TCP header
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + ETHER_HDR_LEN + (ip_header->ip_hl << 2));
            
            // Extract TCP information
            printf("Source Port: %d\n", ntohs(tcp_header->th_sport));
            printf("Destination Port: %d\n", ntohs(tcp_header->th_dport));
        }
    }

    printf("\n");
}

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


        // (b) - reverse dns lookup



        // question 2
        // 1 - check for the flag keyword
        packet_flag_data(packet, n_pac);

        // 2 - check for the user name = secret
        extract_secret(packet, n_pac);

        // 3 - for TCP checksum  =  "0x0ac4" 
        check_sum(packet, n_pac);

        // 4 - IP address of device =  "131.144.126.118" , find the sum of src and des port
        Find_port_sum(packet, n_pac);

        // 5 - flavour of milkshake
        analyze_packet_milkshake(packet, n_pac);
        
        free(packet);
    }

    close(raw_s); // Close the socket when you're done with it
    return 0;
}