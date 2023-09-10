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


// milkshake
void analyze_packet_milkshake(const unsigned char *packet, int packet_size) {
    
    struct ether_header *eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        // Extract IP information
        struct ip *ip_header = (struct ip *)(packet + ETHER_HDR_LEN);
        
        //checking that packet has came from localhost
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

// check sum data
void check_sum(const unsigned char *packet, int packet_size){
    struct ether_header *eth_header = (struct ether_header *)packet;
    struct ip *ip_header = (struct ip *)(packet + ETHER_HDR_LEN);
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + ETHER_HDR_LEN + (ip_header->ip_hl << 2));
    if (ntohs(tcp_header->th_sum) == 0x0ac4) {
        printf("Found TCP checksum '0x0ac4' in a TCP packet.\n");
        char *tcp_data = (char *)(packet + ETHER_HDR_LEN + (ip_header->ip_hl << 2) + (tcp_header->th_off << 2));
        printf("Packet Data:\n%s\n", tcp_data);
    }
}


//given ip address, need to get sum of port
void Find_port_sum(unsigned char *packet, int packet_size) {

    struct ether_header *eth_header = (struct ether_header *)packet;

    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip *)(packet + ETHER_HDR_LEN);

        if( strcmp(inet_ntoa(ip_header->ip_src) ,"131.144.126.118") || strcmp(inet_ntoa(ip_header->ip_dst), "131.144.126.118")){ //||  strcmp(inet_ntoa(ip_header->ip_dst), "131.144.126.118")
            if (packet_size >= (ETHER_HDR_LEN + (ip_header->ip_hl << 2) + sizeof(struct tcphdr))) {
                // Check if there's enough data for a TCP header
                struct tcphdr *tcp_header = (struct tcphdr *)(packet + ETHER_HDR_LEN + (ip_header->ip_hl << 2));
                
                
                int src = ntohs(tcp_header->th_sport);
                int des =  ntohs(tcp_header->th_dport); 
                int s = src + des;
                // printf("%d",  s);
                char *tcp_data = (char *)(packet + ETHER_HDR_LEN + (ip_header->ip_hl << 2) + (tcp_header->th_off << 2));
                if(packet_size >= (ETHER_HDR_LEN + (ip_header->ip_hl << 2) + (tcp_header->th_off << 2)) ){
                    printf("sum of the ports : %d \n",  s);
                    printf("Packet Data:\n%s\n", tcp_data);
                } 
                printf("\n");
            }   
        }
    }
}




//secret username
void extract_secret(const unsigned char *packet, int packet_size) {
    struct ether_header *eth_header = (struct ether_header *)packet;

    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        
        struct ip *ip_header = (struct ip *)(packet + ETHER_HDR_LEN);

        if (ip_header->ip_p == IPPROTO_TCP) {
         
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + ETHER_HDR_LEN + (ip_header->ip_hl << 2));
            
   
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
            // no use
        }
    }
}


// check flag
void packet_flag_data(unsigned char *packet, int packet_size){
    struct ether_header *eth_header = (struct ether_header *)packet;


    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
  
        struct ip *ip_header = (struct ip *)(packet + ETHER_HDR_LEN);

      
        if (ip_header->ip_p == IPPROTO_TCP) {
            
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + ETHER_HDR_LEN + (ip_header->ip_hl << 2));
            
            
            int tcp_data_length = packet_size - ETHER_HDR_LEN - (ip_header->ip_hl << 2) - (tcp_header->th_off << 2);

            if (tcp_data_length > 0) {
                char *tcp_data = (char *)(packet + ETHER_HDR_LEN + (ip_header->ip_hl << 2) + (tcp_header->th_off << 2));
                // char *secret_keyword = "flag";
                
                // Search for the flag keyword in TCP data
                if (strstr(tcp_data, "Flag") != NULL) {
                    printf("Found Flag keyword in a TCP packet: \n");
                    printf("Packet Data : \n%s\n", tcp_data);
                    printf("\n");
                }
            }
        } else if (ip_header->ip_p == IPPROTO_UDP) {
            // UDP packet
            // Similar extraction logic as TCP for UDP packets if needed
        }
    }
}

void packet_information(unsigned char *packet, int packet_size) {

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
