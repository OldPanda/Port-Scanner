#ifndef _PS_LIB_H_
#define _PS_LIB_H_

//#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <time.h>
#include <errno.h>
#include <poll.h>
#include <fcntl.h> // set sockets to be nonblock
#include <pthread.h> // multi-thread
#include <netdb.h>

#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h> //ip hdeader library (must come before ip_icmp.h)
#include <netinet/ip_icmp.h> //icmp header
#include <net/if.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h> //internet address library
//#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <sys/socket.h>
#include <ifaddrs.h>

#include "ps_lib.h"

#define PORT_NUM 65536
#define FILE_NAME_MAX 1024
#define IP_ADDR_LEN 20
#define DATAGRAM_SIZE 4096
#define LOCAL_PORT 54321 // pick arbitrarily
#define TRANS_TIMEOUT 1 // 1 second
#define RETRANS_TIMES 3 // do retransmission at most 3 times

// scan types
#define SYN 0
#define NUL 1
#define FIN 2
#define XMAS 3
#define ACK 4
#define UDP 5

static struct option long_options[] = {
    /* These options don’t set a flag.
     We distinguish them by their indices. */
    {"help",    no_argument,       0, 'h'},
    {"ports",   required_argument, 0, 'p'},
    {"ip",      required_argument, 0, 'i'},
    {"prefix",  required_argument, 0, 'r'},
    {"file",    required_argument, 0, 'f'},
    {"speedup", required_argument, 0, 's'},
    {"scan",    required_argument, 0, 'c'},
    {0, 0, 0, 0}
};

typedef struct {
    int ports[PORT_NUM]; // port array, 0: not check this port; 1: check this port
    char **ip_addr; // can be allocated dynamically
    int ip_num; // how many ip addresses
    int threads; // number of threads
    int scan_types[6]; // six scan types
} ps_args_t;

// used for tcp checksum
struct tcp_pseudo_hdr {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t reserved;
    u_int8_t protocol;
    u_int16_t length;
    struct tcphdr tcp;
};

// udp checksum
struct udp_pseudo_hdr {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t reserved;
    u_int8_t protocol;
    u_int16_t length;
    struct udphdr udp;
};

// DNS header structure
// reference: http://www.binarytides.com/dns-query-code-in-c-with-linux-sockets/
struct DNS_HEADER {
    unsigned short id; // identification number

    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag

    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available

    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};

typedef struct {
    char ip_address[IP_ADDR_LEN];
    int port;
    int scan_type;
    char state[20];
    char service[64];
} results;

extern char source_ip[INET_ADDRSTRLEN]; // local ip address
extern struct sockaddr_in dest_addr; // dest ip address
extern char scan_name[6][5]; // print scan names

/*
 * connection(int socket, ps_args_t *ps_args) -> void
 *
 * Make connection to target ip addresses and ports.
 */
void connection(int socket, ps_args_t *ps_args);

/*
 * get_local_ip(char *source_ip) -> void
 *
 * get local ip address as source ip in tcp or udp header.
 * http://stackoverflow.com/questions/212528/get-the-ip-address-of-the-machine
 */
void get_local_ip(char *source_ip);

/*
 * u_int16_t cal_checksum(unsigned short *ptr, int byte_num) -> u_int16_t
 *
 * Calculate checksum for headers.
 * Reference: http://sock-raw.org/papers/syn_scanner
 *            http://www.roman10.net/how-to-calculate-iptcpudp-checksumpart-1-theory
 */
u_int16_t cal_checksum(u_int16_t *ptr, int byte_num);

/*
 * build_ip_header(struct iphdr *ip_header, char *datagram) -> void
 *
 * build ip header given protocol
 */
void build_ip_header(struct iphdr *ip_header, char *datagram, u_int8_t protocol, struct sockaddr_in dest_addr);

/*
 * build_tcp_header(struct tcphdr *tcp_header, int port, int scan_type) -> void
 *
 * build tcp header based on given port and scan type
 */
void build_tcp_header(struct tcphdr *tcp_header, int port, int scan_type);

/*
 * build_udp_header(struct udphdr *udp_header, int port) -> void
 *
 * build udp header
 */
void build_udp_header(struct udphdr *udp_header, int port);

/*
 * build_dns_header() -> void
 *
 * build dns header when doing udp scan and port is 53
 */
void build_dns_header(struct DNS_HEADER *dns_header);

/*
 * tcp_scan(char *ip_address, int port, int scan_type) -> void
 *
 * do tcp scanning given ip address, port and scan type, then parse the returned packet.
 * Reference: http://www.binarytides.com/
 */
results tcp_scan(char *ip_address, int port, int scan_type, int thread);

/*
 * udp_scan(char *ip_address, int port) ->void
 *
 * udp scan
 */
results udp_scan(char *ip_address, int port, int thread);

/*
 * get_service_response(char *message, char *recv_buf) -> void
 *
 * get response from specific port
 */
void get_service_response(char *message, char *recv_buf, struct sockaddr_in dest_addr);

/*
 * check_services(int port, char *result) -> void
 *
 * to verify services on specific ports, results are kept in result
 */
void check_services(int port, char *result, struct sockaddr_in dest_addr);

/*
 * check_http(char *recv_buf, char *result) -> void
 *
 * verify http service
 */
void check_http(char *recv_buf, char *result, struct sockaddr_in dest_addr);

/*
 * check_ssh(char *recv_buf, char *result) -> void
 *
 * verify ssh service
 */
void check_ssh(char *recv_buf, char *result, struct sockaddr_in dest_addr);

/*
 * check_smtp(char *recv_buf, char *result) -> void
 *
 * verify smtp service
 */
void check_smtp(char *recv_buf, char *result, struct sockaddr_in dest_addr);

/*
 * check_pop(char *recv_buf, char *result) -> void
 *
 * verify pop service
 */
void check_pop(char *recv_buf, char *result, struct sockaddr_in dest_addr);

/*
 * check_whois(char *recv_buf, char *result) -> void
 *
 * verify whois service
 */
void check_whois(char *recv_buf, char *result, struct sockaddr_in dest_addr);

/*
 * check_imap(char *recv_buf, char *result) -> void
 *
 * verify imap service
 */
void check_imap(char *recv_buf, char *result, struct sockaddr_in dest_addr);

#endif
