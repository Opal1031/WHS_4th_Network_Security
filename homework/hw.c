#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h"   // header Structures

// print Mac address
void print_mac(u_char *mac)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// print Message data
void print_message(const u_char *data, int len)
{
    int i;

    for (i = 0; i < len; i++) {
        printf("%c", data[i]);
    }

    printf("\n");
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800) {
        struct ipheader *ip = (struct ipheader *)
                              (packet + sizeof(struct ethheader));

        // Calculate IP Header length
        int ip_header_len = ip->iph_ihl * 4;

        // Locate TCP header
        struct tcpheader *tcp = (struct tcpheader *)
                                (packet + sizeof(struct ethheader)
                                        + ip_header_len);

        // Calculate TCP Header length
        int tcp_header_len = TH_OFF(tcp) * 4;

        // Calculate payload length
        int ip_total_len = ntohs(ip->iph_len);
        int data_len = ip_total_len - ip_header_len - tcp_header_len;

        // Locate Application data
        const u_char *data = packet + sizeof(struct ethheader)
                                    + ip_header_len
                                    + tcp_header_len;

        printf("\n========== TCP Packet ==========\n");

        printf("[Ethernet Header]\n");
        printf("Src MAC: ");
        print_mac(eth->ether_shost);
        printf("\nDst MAC: ");
        print_mac(eth->ether_dhost);
        printf("\n");

        printf("[IP Header]\n");
        printf("Src IP : %s\n", inet_ntoa(ip->iph_sourceip));
        printf("Dst IP : %s\n", inet_ntoa(ip->iph_destip));

        printf("[TCP Header]\n");
        printf("Src Port: %d\n", ntohs(tcp->tcp_sport));
        printf("Dst Port: %d\n", ntohs(tcp->tcp_dport));

        printf("[HTTP Message]\n");
        print_message(data, data_len);
        printf("\n================================\n");
    }
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;

    // Filter tcp packets
    char filter_exp[] = "tcp and host 192.168.64.3 and port 8080";
    bpf_u_int32 net;

    handle = pcap_open_live("enp0s1", BUFSIZ, 1, 1000, errbuf);

    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}