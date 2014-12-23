#include "ps_lib.h"
#include "ps_setup.h"

/*
 * get_local_ip(char *source_ip) -> void
 *
 * get local ip address as source ip in tcp or udp header.
 * http://stackoverflow.com/questions/212528/get-the-ip-address-of-the-machine
 */
void get_local_ip(char *source_ip) {
    struct ifaddrs *if_addr_struct = NULL;
    struct ifaddrs *ifa = NULL;
    void *tmp_addr_ptr = NULL;

    getifaddrs(&if_addr_struct);
    for (ifa = if_addr_struct; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) {
            continue;
        }
        if (ifa->ifa_addr->sa_family == AF_INET) {
            if (!strcmp(ifa->ifa_name, "eth0")) {
                tmp_addr_ptr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
                inet_ntop(AF_INET, tmp_addr_ptr, source_ip, INET_ADDRSTRLEN);
            }
        }
    }

    if (if_addr_struct != NULL)
        freeifaddrs(if_addr_struct);

    // printf("Source ip address: %s\n", source_ip);
}

/*
 * cal_checksum(unsigned short *ptr, int byte_num) -> u_int16_t
 *
 * Calculate checksum for headers.
 * Reference: http://sock-raw.org/papers/syn_scanner
 *            http://www.roman10.net/how-to-calculate-iptcpudp-checksumpart-1-theory
 */
u_int16_t cal_checksum(u_int16_t *ptr, int nbytes) {
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum = 0;
    while(nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if(nbytes == 1) {
        oddbyte = 0;
        *((u_char*)&oddbyte) = *(u_char*)ptr;
        sum += oddbyte;
    }

    sum = (sum>>16) + (sum & 0xffff);
    sum = sum + (sum>>16);
    answer = (short)~sum;

    return answer;
}

/*
 * build_ip_header(struct iphdr *ip_header, char *datagram) -> void
 *
 * build ip header given protocol
 */
void build_ip_header(struct iphdr *ip_header, char *datagram, u_int8_t protocol, struct sockaddr_in dest_addr) {
    int transport_len = (protocol == IPPROTO_TCP)? sizeof(struct tcphdr): sizeof(struct udphdr);
    ip_header->ihl = 5;
    ip_header->version = 4;
    ip_header->tos = 0;
    ip_header->tot_len = sizeof(struct iphdr) + transport_len;
    ip_header->id = htons(12345); //Id of this packet, pick arbitrarily
    ip_header->frag_off = 0;
    ip_header->ttl = 64;
    ip_header->protocol = protocol;
    ip_header->check = 0;
    ip_header->saddr = inet_addr(source_ip);
    ip_header->daddr = dest_addr.sin_addr.s_addr;
    ip_header->check = cal_checksum((unsigned short *)datagram, ip_header->tot_len>>1);
}

/*
 * build_tcp_header(struct tcphdr *tcp_header, int port, int scan_type) -> void
 *
 * build tcp header based on given port and scan type
 */
void build_tcp_header(struct tcphdr *tcp_header, int port, int scan_type) {
    tcp_header->source = htons(LOCAL_PORT);
    tcp_header->dest = htons(port);
    tcp_header->seq = htonl(rand()); // random
    tcp_header->ack_seq = 0;
    tcp_header->doff = sizeof(struct tcphdr) / 4;
    tcp_header->fin = (scan_type == FIN)? 1: 0;
    tcp_header->syn = (scan_type == SYN)? 1: 0;
    tcp_header->rst = 0;
    tcp_header->psh = 0;
    tcp_header->ack = (scan_type == ACK)? 1: 0;
    tcp_header->urg = 0;

    if (scan_type == XMAS) {
        tcp_header->fin = 1;
        tcp_header->psh = 1;
        tcp_header->urg = 1;
    }

    tcp_header->window = htons(14600);  // maximum allowed window size
    tcp_header->check = 0; // leave to be assigned later
    tcp_header->urg_ptr = 0;
}

/*
 * build_udp_header(struct udphdr *udp_header, int port) -> void
 *
 * build udp header
 */
void build_udp_header(struct udphdr *udp_header, int port) {
    udp_header->source = htons(LOCAL_PORT);
    udp_header->dest = htons(port);
    udp_header->len = htons(sizeof(struct udphdr));
    udp_header->check = 0;
}

/*
 * This will convert www.google.com to 3www6google3com
 * got it :)
 * */
void ChangetoDnsNameFormat(unsigned char* dns,unsigned char* host)
{
    int lock = 0 , i;
    strcat((char*)host,".");
     
    for(i = 0 ; i < strlen((char*)host) ; i++)
    {
        if(host[i]=='.')
        {
            *dns++ = i-lock;
            for(;lock<i;lock++)
            {
                *dns++=host[lock];
            }
            lock++; //or lock=i+1;
        }
    }
    *dns++='\0';
}

/*
 * build_dns_header() -> void
 *
 * build dns header when doing udp scan and port is 53
 * reference: http://www.binarytides.com/dns-query-code-in-c-with-linux-sockets/
 */
void build_dns_header(struct DNS_HEADER *dns_header) {
    dns_header->id = (unsigned short)htons(getpid());
    /*
    dns_header->qr = 0; //This is a query
    dns_header->opcode = 0; //This is a standard query
    dns_header->aa = 0; //Not Authoritative
    dns_header->tc = 0; //This message is not truncated
    dns_header->rd = 1; //Recursion Desired
    dns_header->ra = 0; //Recursion not available!
    dns_header->z = 0;
    dns_header->ad = 0;
    dns_header->cd = 0;
    dns_header->rcode = 0;
    */
    dns_header->flag = htons(0x0100);
    dns_header->q_count = htons(1);
    dns_header->ans_count = 0;
    dns_header->auth_count = 0;
    dns_header->add_count = 0;
}

/*
 * tcp_scan(char *ip_address, int port, int scan_type) -> void
 *
 * do tcp scanning given ip address, port and scan type, then parse the returned packet.
 * return a results structure which contains scan information
 * Reference: http://www.binarytides.com/
 */
results tcp_scan(char *ip_address, int port, int scan_type, int thread) {
    // for building headers
    char datagram[DATAGRAM_SIZE];
    int i; // for any loops
    int retrans_num = 0; // do retransmission at most 3 times
    int if_retrans = 1; // if need to retransmit packet
    struct timeval start_time;
    struct timeval cur_time;
    struct pollfd poll_set[2]; // recv_sock; icmp_recv_sock
    int numfds = 2;
    int flags; // set to nonblock refer: http://blog.csdn.net/houlaizhe221/article/details/6580775
    // for receive and parse packets
    int poll_res;
    unsigned char *buffer;
    char *icmp_buffer;
    int recv_sock;
    int icmp_recv_sock; // receive icmp packet
    int saddr_size, data_size;
    struct sockaddr source_addr;
    struct sockaddr_in dest_addr;
    // service verification
    char ser_result[64];
    memset(ser_result, 0, 64);
    results res;

    memset(&res, 0, sizeof(results));

    strcpy(res.ip_address, ip_address);
    res.port = port;
    res.scan_type = scan_type;

    // raw socket
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    if(sock < 0) {
        // printf("Error creating socket. Error number: %d. Error message: %s\n", errno, strerror(errno));
        exit(0);
    }

    // set 0 to datagram
    memset(datagram, 0, DATAGRAM_SIZE);

    // assign dest ip address and port
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    dest_addr.sin_addr.s_addr = inet_addr(ip_address);

    printf("\nIP address: %s. Port: %d. Thread: %d. Scan: %s\n", ip_address, port, thread, scan_name[scan_type]);

    // ip header
    struct iphdr *ip_header = (struct iphdr *)datagram;
    // tcp header
    struct tcphdr *tcp_header = (struct tcphdr *)(datagram + sizeof(struct iphdr));
    // pseudo header used for checksum
    struct tcp_pseudo_hdr pseudo_header;

    build_ip_header(ip_header, datagram, IPPROTO_TCP, dest_addr);
    build_tcp_header(tcp_header, port, scan_type);

    // IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;

    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        // printf("Error setting IP_HDRINCL. Error number: %d. Error message: %s\n", errno, strerror(errno));
        exit(0);
    }

    // build tcp pseudo header
    pseudo_header.source_address = inet_addr(source_ip);
    pseudo_header.dest_address = dest_addr.sin_addr.s_addr;
    pseudo_header.reserved = 0;
    pseudo_header.protocol = IPPROTO_TCP;
    pseudo_header.length = htons(sizeof(struct tcphdr));
    memcpy(&pseudo_header.tcp, tcp_header, sizeof(struct tcphdr));

    tcp_header->check = cal_checksum((unsigned short*)&pseudo_header, sizeof(struct tcp_pseudo_hdr));

    recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (recv_sock < 0) {
        // printf("Error creating receive socket. Error number: %d. Error message: %s\n", errno, strerror(errno));
        exit(0);
    }

    icmp_recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (icmp_recv_sock < 0) {
        // printf("Error creating icmp_recv socket. Error number: %d. Error message: %s\n", errno, strerror(errno));
        exit(0);
    }

    // init poll set
    poll_set[0].fd = recv_sock;
    poll_set[0].events = POLLIN | POLLERR;
    poll_set[1].fd = icmp_recv_sock;
    poll_set[1].events = POLLIN | POLLERR;

    buffer = (unsigned char *)calloc(65536, sizeof(unsigned char)); // used for receiving message
    icmp_buffer = (char *)calloc(65536, sizeof(char));

    // this part refered to what I did in bittorrent project
    while (if_retrans) {
        if (sendto(sock, datagram , sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
            // printf("Error sending tcp packet. Error number: %d. Error message: %s\n", errno, strerror(errno));
            break;
        }

        // struct timeval timeout;
        gettimeofday(&start_time, NULL); // as the start time of current loop

        while (1) {

            poll_res = poll(poll_set, numfds, TRANS_TIMEOUT * 1000);

            if (poll_res == -1) {
                // printf("Poll error. \n");
                if_retrans = 0;
                break;
            }
            else if (poll_res == 0) {
                // printf("Timeout: no data received. \n");
            }
            else { // receive and parse data
                if (poll_set[0].revents & POLLIN) { // recv_sock
                    saddr_size = sizeof(source_addr);
                    data_size = recvfrom(recv_sock, buffer, 65536, 0, &source_addr, &saddr_size);

                    if (data_size < 0) {
                        // printf("Recvfrom error, failed to get packets. Error num: %d. Error message: %s\n",
                        //     errno, strerror(errno));
                        if_retrans = 0;
                        // retrans_num = 10;
                        break;
                    }

                    struct iphdr *iph = (struct iphdr*)buffer;
                    struct sockaddr_in source, dest;
                    unsigned short iphdr_len;

                    if (iph->protocol == IPPROTO_TCP) {
                        iphdr_len = iph->ihl * 4;
                        struct tcphdr *tcph = (struct tcphdr*)(buffer + iphdr_len);

                        memset(&source, 0, sizeof(source));
                        source.sin_addr.s_addr = iph->saddr;

                        memset(&dest, 0, sizeof(dest));
                        dest.sin_addr.s_addr = iph->daddr;

                        if (scan_type == SYN) { // only do SYN scan now
                            if (tcph->syn == 1 && source.sin_addr.s_addr == dest_addr.sin_addr.s_addr && ntohs(tcph->source) == port) {
                                if_retrans = 0;
                                // printf("TCP %s scan: port %d open. Thread: %d\n", scan_name[scan_type], port, thread);
                                // fflush(stdout);
                                strcpy(res.state, "open");
                                // check_services(port, result);
                                break;
                            }
                            else if (tcph->rst == 1 && tcph->ack == 1 && source.sin_addr.s_addr == dest_addr.sin_addr.s_addr && ntohs(tcph->source) == port) {
                                if_retrans = 0;
                                // printf("TCP %s scan: port %d closed. Thread: %d\n", scan_name[scan_type], port, thread);
                                // fflush(stdout);
                                strcpy(res.state, "closed");
                                break;
                            }
                        }
                        else if (scan_type == NUL || scan_type == FIN || scan_type == XMAS) {
                            // only handle closed case
                            if (tcph->rst == 1 && tcph->ack == 1 && source.sin_addr.s_addr == dest_addr.sin_addr.s_addr && ntohs(tcph->source) == port) {
                                if_retrans = 0;
                                // printf("TCP %s scan: port %d closed. Thread: %d\n", scan_name[scan_type], port, thread);
                                // fflush(stdout);
                                strcpy(res.state, "closed");
                                break;
                            }
                        }
                        else if (scan_type == ACK) {
                            if (tcph->rst == 1 && source.sin_addr.s_addr == dest_addr.sin_addr.s_addr && ntohs(tcph->source) == port) {
                                if_retrans = 0;
                                // printf("TCP %s scan: port %d unfiltered. Thread: %d\n", scan_name[scan_type], port, thread);
                                // fflush(stdout);
                                strcpy(res.state, "unfiltered");
                                break;
                            }
                        }
                    }
                } // end of recv_sock
                else if (poll_set[1].revents & POLLIN) { // icmp packet
                    saddr_size = sizeof(source_addr);
                    data_size = recvfrom(recv_sock, icmp_buffer, 65536, 0, &source_addr, &saddr_size);

                    if (data_size < 0) {
                        // printf("Recvfrom error, failed to get packets. Error num: %d. Error message: %s\n",
                        //     errno, strerror(errno));
                        if_retrans = 0;
                        //retrans_num = 10;
                        break;
                    }

                    struct iphdr *iph = (struct iphdr*)icmp_buffer;
                    unsigned short iphdr_len;

                    iphdr_len = iph->ihl * 4;
                    struct icmphdr *icmph = (struct icmphdr*)(icmp_buffer + iphdr_len);
                    struct iphdr *ori_iph = (struct iphdr*)(icmp_buffer + iphdr_len + sizeof(struct icmphdr));
                    struct tcphdr *ori_tcph = (struct tcphdr*)(icmp_buffer + iphdr_len + sizeof(struct icmphdr) + ori_iph->ihl * 4);

                    if ((ori_iph->daddr == dest_addr.sin_addr.s_addr) && (ntohs(ori_tcph->dest) == port) && (LOCAL_PORT == ntohs(ori_tcph->source))) {
                        if (icmph->type == 3 && (icmph->code == 1 ||
                                                 icmph->code == 2 ||
                                                 icmph->code == 3 ||
                                                 icmph->code == 9 ||
                                                 icmph->code == 10 ||
                                                 icmph->code == 13)) {
                            if_retrans = 0;
                            // printf("TCP %s scan: ICMP packet received, port %d filtered. \n",
                            //      scan_name[scan_type], port);
                            strcpy(res.state, "filtered");
                            break;
                        }
                    }

                } // end of icmp_recv_sock
            } // end else

            if (if_retrans) {
                gettimeofday(&cur_time, NULL);
                if ((cur_time.tv_sec - start_time.tv_sec) > TRANS_TIMEOUT) {
                    // if waiting time runs out in this loop, do retransmission
                    retrans_num++;
                    break;
                }
            }
        } // end of while(1)

        if (retrans_num >= RETRANS_TIMES) { // no response
            if_retrans = 0;
            if (scan_type == SYN) {
                // printf("TCP %s scan: port %d filtered. \n", scan_name[scan_type], port);
                strcpy(res.state, "filtered");
            }
            else {
                // printf("TCP %s scan: port %d open | filtered. \n", scan_name[scan_type], port);
                strcpy(res.state, "open | filtered");
            }
        }
    } // end of while(if_retrans)

    check_services(port, ser_result, dest_addr);
    strcpy(res.service, ser_result);

    close(sock);
    close(recv_sock);
    close(icmp_recv_sock);
    free(buffer);
    free(icmp_buffer);

    // printf("End thread: %d\n", thread);
    return res;
}

/*
 * udp_scan(char *ip_address, int port) ->void
 *
 * udp scan
 */
results udp_scan(char *ip_address, int port, int thread) {
    // for building headers
    char datagram[DATAGRAM_SIZE];
    int i;
    int retrans_num = 0; // do retransmission at most 5 times
    int if_retrans = 1; // if need to retransmit packet
    struct timeval start_time;
    struct timeval cur_time;
    struct pollfd poll_set[2]; // icmp_recv_sock
    int numfds = 2;
    int flags; // set to nonblock refer: http://blog.csdn.net/houlaizhe221/article/details/6580775
    // for receive and parse packets
    int select_res;
    int poll_res;
    char *icmp_buffer; // icmp
    unsigned char *buffer; // udp
    int icmp_recv_sock;
    int udp_recv_sock; // receive udp packet
    int saddr_size, data_size;
    struct sockaddr source_addr;
    struct sockaddr_in dest_addr;
    // services
    char ser_result[128];
    memset(ser_result, 0, 128);
    results res;

    memset(&res, 0, sizeof(results));

    strcpy(res.ip_address, ip_address);
    res.port = port;
    res.scan_type = UDP;

    // raw sock
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock < 0) {
        // printf("Error creating socket. Error number: %d. Error message: %s\n", errno, strerror(errno));
        exit(0);
    }

    // set 0 to datagram
    memset(datagram, 0, DATAGRAM_SIZE);

    // assign dest ip address and port
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    dest_addr.sin_addr.s_addr = inet_addr(ip_address);

    printf("\nIP address: %s. Port: %d. Thread: %d. Scan: UDP\n", ip_address, port, thread);

    // ip header
    struct iphdr *ip_header = (struct iphdr *)datagram;
    // tcp header
    struct udphdr *udp_header = (struct udphdr *)(datagram + sizeof(struct iphdr));
    // pseudo header used for checksum
    struct udp_pseudo_hdr pseudo_header;

    build_ip_header(ip_header, datagram, IPPROTO_UDP, dest_addr);
    build_udp_header(udp_header, port);

    // build dns header if port is 53
    unsigned char *qname;
    if (port == 53) {
        struct DNS_HEADER *dns_header = (struct DNS_HEADER *)(datagram
                                        + sizeof(struct iphdr) + sizeof(struct udphdr));
        build_dns_header(dns_header);

        qname = (unsigned char *)(datagram + sizeof(struct iphdr) 
                + sizeof(struct udphdr) 
                + sizeof(struct DNS_HEADER));
        unsigned char host[20] = "www.google.com";
        ChangetoDnsNameFormat(qname, host);
        // memcpy(qname, "3www6google3com\0", 16);
        
        struct QUESTION *qinfo = (struct QUESTION *)(datagram + sizeof(struct iphdr) + sizeof(struct udphdr)
                + sizeof(struct DNS_HEADER)
                + (strlen((const char *)qname)) + 1);
        qinfo->qtype = htons(1); // type A
        qinfo->qclass = htons(1); // IN

        ip_header->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) 
                + sizeof(struct DNS_HEADER)
                + (strlen((const char *)qname)) + 1 + sizeof(struct QUESTION);
        udp_header->len = htons(sizeof(struct udphdr) + sizeof(struct DNS_HEADER)
                + (strlen((const char *)qname)) + 1 + sizeof(struct QUESTION));
        // printf("IP len: %d\n", ip_header->tot_len);
        // printf("dns header: %2X\n", dns_header);
        // printf("qname: %s\n", qname);
        // printf("qtype: %u\n", qinfo->qtype);
        // printf("qclass: %u\n", qinfo->qclass);
    }

    // IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;

    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        // printf("Error setting IP_HDRINCL. Error number: %d. Error message: %s\n", errno, strerror(errno));
        exit(0);
    }

    // build tcp pseudo header
    pseudo_header.source_address = inet_addr(source_ip);
    pseudo_header.dest_address = dest_addr.sin_addr.s_addr;
    pseudo_header.reserved = 0;
    pseudo_header.protocol = IPPROTO_UDP;
    
    if (port == 53) {
        pseudo_header.length = htons(sizeof(struct udphdr) + sizeof(struct DNS_HEADER)
                + (strlen((const char *)qname)) + 1 + sizeof(struct QUESTION));
    }
    else {
        pseudo_header.length = htons(sizeof(struct udphdr));
    }
    memcpy(&pseudo_header.udp, udp_header, sizeof(struct udphdr));

    udp_header->check = cal_checksum((unsigned short*)&pseudo_header, sizeof(struct udp_pseudo_hdr));

    icmp_recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (icmp_recv_sock < 0) {
        // printf("Error creating icmp receive socket. Error number: %d. Error message: %s\n", errno, strerror(errno));
        exit(0);
    }

    udp_recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (udp_recv_sock < 0) {
        // printf("Error creating udp receive socket. Error number: %d. Error message: %s\n", errno, strerror(errno));
        exit(0);
    }

    // init poll set
    poll_set[0].fd = icmp_recv_sock;
    poll_set[0].events = POLLIN | POLLERR;
    poll_set[1].fd = udp_recv_sock;
    poll_set[1].events = POLLIN | POLLERR;

    icmp_buffer = (char *)malloc(65536 * sizeof(char));
    buffer = (unsigned char *)malloc(65536 * sizeof(unsigned char));

    while (if_retrans) {
        if (sendto(sock, datagram, ip_header->tot_len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
            // printf("Error sending udp packet. Error number: %d. Error message: %s\n", errno, strerror(errno));
            break;
        }
        gettimeofday(&start_time, NULL);

        memset(icmp_buffer, 0, 65536);
        memset(buffer, 0, 65536);

        while (1) {
            poll_res = poll(poll_set, numfds, TRANS_TIMEOUT * 1000);

            if (poll_res == -1) {
                // printf("Poll error. \n");
                if_retrans = 0;
                break;
            }
            else if (poll_res == 0) {
                // printf("Timeout: no data received. \n");
            }
            else {
                if (poll_set[0].revents & POLLIN) { // receive a icmp packet
                    saddr_size = sizeof(source_addr);
                    data_size = recvfrom(icmp_recv_sock, icmp_buffer, 65536, 0, &source_addr, &saddr_size);

                    if (data_size < 0) {
                        // printf("Recvfrom error, failed to get packets\n");
                        if_retrans = 0;
                        // retrans_num = 10; // assign a large number to set it filtered
                        break;
                    }

                    struct iphdr *iph = (struct iphdr*)icmp_buffer;
                    unsigned short iphdr_len;

                    iphdr_len = iph->ihl * 4;
                    struct icmphdr *icmph = (struct icmphdr*)(icmp_buffer + iphdr_len);
                    struct iphdr *ori_iph = (struct iphdr*)(icmp_buffer + iphdr_len + sizeof(struct icmphdr));
                    struct udphdr *ori_udph = (struct udphdr*)(icmp_buffer + iphdr_len + sizeof(struct icmphdr) + ori_iph->ihl * 4);

                    if (ori_iph->daddr == dest_addr.sin_addr.s_addr && ntohs(ori_udph->dest) == port && LOCAL_PORT == ntohs(ori_udph->source)) {
                        if (icmph->type == 3 && (icmph->code == 1 ||
                                                 icmph->code == 2 ||
                                                 icmph->code == 9 ||
                                                 icmph->code == 10 ||
                                                 icmph->code == 13)) {
                            if_retrans = 0;
                            // printf("UDP scan: ICMP packet received, port %d filtered. \n", port);
                            strcpy(res.state, "filtered");
                            break;
                        }
                        else if (icmph->type == 3 && icmph->code == 3) {
                            if_retrans = 0;
                            // printf("UDP scan: ICMP packet received, port %d closed. \n", port);
                            strcpy(res.state, "closed");
                            break;
                        }
                    }

                }
                else if (poll_set[1].revents & POLLIN) { // receive a udp packet
                    saddr_size = sizeof(source_addr);
                    data_size = recvfrom(udp_recv_sock, buffer, 65536, 0, &source_addr, &saddr_size);

                    if (data_size < 0) {
                        // printf("Recvfrom error, failed to get packets\n");
                        if_retrans = 0;
                        //retrans_num = 10;
                        break;
                    }

                    struct iphdr *iph = (struct iphdr*)buffer;
                    struct sockaddr_in source, dest;
                    unsigned short iphdr_len;

                    if (iph->protocol == IPPROTO_UDP) {
                        iphdr_len = iph->ihl * 4;
                        struct udphdr *udph = (struct udphdr*)(buffer + iphdr_len);

                        memset(&source, 0, sizeof(source));
                        source.sin_addr.s_addr = iph->saddr;

                        memset(&dest, 0, sizeof(dest));
                        dest.sin_addr.s_addr = iph->daddr;

                        if (source.sin_addr.s_addr == dest_addr.sin_addr.s_addr && (ntohs(udph->source) == port)) {
                            if_retrans = 0;
                            // printf("UDP scan: port %d open. \n", port);
                            strcpy(res.state, "open");
                            // fflush(stdout);
                            //check_services(port, result);
                            break;
                        }
                    }
                }
            } // end else

            if (if_retrans) {
                gettimeofday(&cur_time, NULL);
                if ((cur_time.tv_sec - start_time.tv_sec) > TRANS_TIMEOUT) {
                    // if waiting time runs out in this loop, do retransmission
                    retrans_num++;
                    break;
                }
            }
        } // end while (1)

        if (retrans_num >= RETRANS_TIMES) {
            if_retrans = 0;
            // printf("UDP scan: port %d open | filtered. \n", port);
            strcpy(res.state, "open | filtered");
            // fflush(stdout);
        }
    } // end while (if_retrans)

    check_services(port, ser_result, dest_addr);
    strcpy(res.service, ser_result);

    close(sock);
    close(icmp_recv_sock);
    close(udp_recv_sock);
    free(icmp_buffer);
    free(buffer);

    // printf("End thread: %d\n", thread);
    return res;
}

/*
* get_service_response(char *message, char *recv_buf) -> void
*
* get response from specific port
*/
void get_service_response(char *request_msg, char *recv_buf, struct sockaddr_in dest_addr) {
    int service_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (service_sock < 0) {
        close(service_sock);
        printf("Error creating service socket. Error number: %d. Error message: %s\n", errno, strerror(errno));
        return;
    }

    int dest_addr_len = sizeof(dest_addr);
    if (connect(service_sock, (struct sockaddr *)&dest_addr, dest_addr_len) < 0) {
        close(service_sock);
        // printf("Error connection. Error number: %d. Error message: %s\n", errno, strerror(errno));
        return;
    }

    int flags = fcntl(service_sock, F_GETFL, 0);
    fcntl(service_sock, F_SETFL, flags | O_NONBLOCK);

    if (send(service_sock, request_msg, strlen(request_msg), 0) < 0) {
        close(service_sock);
        // printf("Error sending message. Error number: %d. Error message: %s\n", errno, strerror(errno));
        return;
    }

    struct pollfd poll_set[1];
    int poll_res;
    int numfds = 1;
    poll_set[0].fd = service_sock;
    poll_set[0].events = POLLIN | POLLERR;

    poll_res = poll(poll_set, numfds, TRANS_TIMEOUT * 1000);
    int recv_len;

    if (poll_res == -1) {
        close(service_sock);
        // printf("Poll error. \n");
        return;
    }
    else if (poll_res == 0) {

    }
    else {
        if (poll_set[0].revents & POLLIN) {
            recv_len = recv(service_sock, recv_buf, 65536, 0);
            if (recv_len > 0) {
                recv_buf[recv_len] = '\0';
            }
        }
    }
    close(service_sock);
}

/*
 * check_services(int port, char *result) -> void
 *
 * to verify services on specific ports, results are kept in result
 */
void check_services(int port, char *result, struct sockaddr_in dest_addr) {
    char recv_buf[65536];
    memset(recv_buf, 0, 65536);
    if (port == 22) { // ssh
        check_ssh(recv_buf, result, dest_addr);
    }
    else if (port == 24 || port == 25 || port == 587) { // smtp
        check_smtp(recv_buf, result, dest_addr);
    }
    else if (port == 43) { // whois
        check_whois(recv_buf, result, dest_addr);
    }
    else if (port == 80) { // http
        check_http(recv_buf, result, dest_addr);
    }
    else if (port == 110) { // pop3
        check_pop(recv_buf, result, dest_addr);
    }
    else if (port == 143 || port == 993) { // imap
        check_imap(recv_buf, result, dest_addr);
    }
    else {
        // http://stackoverflow.com/questions/4390318/get-running-service-daemon-in-c-on-specific-port
        char port_str[10];
        sprintf(port_str, "%d", port);
        struct addrinfo *ai;
        getaddrinfo(0, port_str, 0, &ai);
        getnameinfo(ai->ai_addr, ai->ai_addrlen, 0, 0, result, sizeof(result), 0);
        freeaddrinfo(ai);
    }
}

/*
 * check_http(char *recv_buf, char *result) -> void
 *
 * verify http service
 */
void check_http(char *recv_buf, char *result, struct sockaddr_in dest_addr) {
    char request_msg[100] = "GET / HTTP\r\n\r\n";
    get_service_response(request_msg, recv_buf, dest_addr);

    if (strlen(recv_buf) > 0) {
        strcpy(result, "HTTP");
        char *http_pos = strstr(recv_buf, "HTTP");
        char version[4];
        memset(version, 0, 4);

        if (http_pos != NULL) {
            strncpy(version, http_pos + strlen("HTTP") + 1, 3);
            strcat(result, " ");
            strcat(result, version);
        }
    }
    else {
        strcpy(result, "Unable to connect. ");
    }
}

/*
 * check_ssh(char *recv_buf, char *result) -> void
 *
 * verify ssh service
 */
void check_ssh(char *recv_buf, char *result, struct sockaddr_in dest_addr) {
    char request_msg[100] = "";
    get_service_response(request_msg, recv_buf, dest_addr);

    if (strlen(recv_buf) > 0) {
        strcpy(result, "SSH");
        char *ssh_pos = strstr(recv_buf, "OpenSSH_");
        char version[4];
        memset(version, 0, 4);

        if (ssh_pos != NULL) {
            strncpy(version, ssh_pos + strlen("OpenSSH_"), 3);
            strcat(result, " ");
            strcat(result, version);
        }
    }
    else {
        strcpy(result, "Unable to connect. ");
    }
}

/*
 * check_smtp(char *recv_buf, char *result) -> void
 *
 * verify smtp service
 */
void check_smtp(char *recv_buf, char *result, struct sockaddr_in dest_addr) {
    char request_msg[100] = "";
    get_service_response(request_msg, recv_buf, dest_addr);

    if (strlen(recv_buf) > 0) {
        strcpy(result, "SMTP");
        char* token = strtok(recv_buf, " ");
        int token_len = strlen(token);

        if (token != NULL) {
            token_len++;
            token = strtok(NULL, " ");
            token_len += strlen(token);
            printf("%s\n", token);
            if (token != NULL) {
                token_len++;
                strcpy(result, " ");
                strcpy(result, &recv_buf[token_len]);
            }
        }
    }
    else {
        strcpy(result, "Unable to connect. ");
    }
}

/*
 * check_pop(char *recv_buf, char *result) -> void
 *
 * verify pop service
 */
void check_pop(char *recv_buf, char *result, struct sockaddr_in dest_addr) {
    char request_msg[100] = "";
    get_service_response(request_msg, recv_buf, dest_addr);

    if (strlen(recv_buf) > 0) {
        strcpy(result, "POP3");
        /*
        char *pop_pos = strstr(recv_buf, "+OK");
        if (pop_pos != NULL) {
            strcpy(result, "POP3");
        }
        */
    }
    else {
        strcpy(result, "Unable to connect. ");
    }
}

/*
 * check_whois(char *recv_buf, char *result) -> void
 *
 * verify whois service
 */
void check_whois(char *recv_buf, char *result, struct sockaddr_in dest_addr) {
    char request_msg[100] = "\r\n";
    get_service_response(request_msg, recv_buf, dest_addr);

    if (strlen(recv_buf) > 0) {
        strcpy(result, "WHOIS");
        char *whois_pos = strstr(recv_buf, "Version");
        char version[4];
        memset(version, 0, 4);

        if (whois_pos != NULL) {
            strncpy(version, whois_pos + strlen("Version") + 1, 3);
            strcat(result, " ");
            strcat(result, version);
        }
    }
    else {
        strcpy(result, "Unable to connect. ");
    }
}

/*
 * check_imap(char *recv_buf, char *result) -> void
 *
 * verify imap service
 */
void check_imap(char *recv_buf, char *result, struct sockaddr_in dest_addr) {
    char request_msg[100] = "";
    get_service_response(request_msg, recv_buf, dest_addr);

    if (strlen(recv_buf) > 0) {
        printf("%s\n", recv_buf);
        strcpy(result, "IMAP");
    }
    else {
        strcpy(result, "Unable to connect. ");
    }
}
