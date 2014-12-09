/*
 * portScanner.c
 * Main procedure for port scanner project. This file includes the header file designed
 * for scanning ports of a given ip addresses. All scanning results will be printed to
 * screen.
 *
 * Author: Wen Chen and Jinhui Zhang
 */

/*
 * References(We got help from following resources).
 * http://www.binarytides.com/raw-sockets-c-code-linux/
 */
#include "ps_lib.h"
#include "ps_setup.h"

char source_ip[INET_ADDRSTRLEN]; // local ip address
//struct sockaddr_in dest_addr; // dest ip address

char scan_name[6][5]; // print scan names
struct DNS_HEADER header; // dns header

struct port_queue *pqueue; // task queue

pthread_mutex_t scan_mutex;
pthread_mutex_t result_mutex;

results *result; // results
int res_index = 0;

ps_args_t ps_args;

// free allocated memories
void free_mem(ps_args_t *ps_args) {
    int i;
    for (i = 0; i < ps_args->ip_num; i++) {
        free(ps_args->ip_addr[i]);
    }
    free(ps_args->ip_addr);
    free(result);
}

void *thread_func(void *id) {
    char ip_address[IP_ADDR_LEN];
    int port;
    int scan_type;
    int thread_id = *((int *)id);

    while (!is_empty(pqueue)) {
        pthread_mutex_lock(&scan_mutex);
        dequeue(pqueue, ip_address, &port);
        pthread_mutex_unlock(&scan_mutex);
        results res;

        for (scan_type = 0; scan_type < 6; scan_type++) {
            if (ps_args.scan_types[scan_type] == 1) {
                if (scan_type == UDP) {
                    res = udp_scan(ip_address, port, thread_id);
                }
                else {
                    res = tcp_scan(ip_address, port, scan_type, thread_id);
                }

                pthread_mutex_lock(&result_mutex);
                memcpy(&result[res_index], &res, sizeof(results));
                res_index++;
                pthread_mutex_unlock(&result_mutex);
            }
        }
    }
}

// print results
void print_res(char *ip_address, int res_size) {
    int i, scan_type;
    for (scan_type = 0; scan_type < 6; scan_type++) { 
        if (ps_args.scan_types[scan_type] == 1) {
            for (i = 0; i < res_size; i++) {
                if (!strcmp(ip_address, result[i].ip_address) && result[i].scan_type == scan_type) {
                    char output[100];
                    memset(output, 0, 100);
                    sprintf(output, "%-4d\t%-27s\t%-10s\t%-s", result[i].port, result[i].service, 
                        scan_name[result[i].scan_type], result[i].state);
                    printf("%s\n", output);
                }
            }
        }
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    int i, port, scan_type;
    void *retval;
    int thread_res;
    int num_ports = 0;
    int num_scans = 0;
    struct timeval start;
    struct timeval end;

    memcpy(&scan_name[0], "SYN", 3);
    memcpy(&scan_name[1], "NULL", 4);
    memcpy(&scan_name[2], "FIN", 3);
    memcpy(&scan_name[3], "XMAS", 4);
    memcpy(&scan_name[4], "ACK", 3);
    memcpy(&scan_name[5], "UDP", 3);

    parse_args(&ps_args, argc, argv);

    for (i = 0; i < PORT_NUM; i++) {
        if (ps_args.ports[i] == 1) {
            num_ports++;
        }
    }

    for (i = 0; i < 6; i++) {
        if (ps_args.scan_types[i] == 1) {
            num_scans++;
        }
    }

    int res_size = ps_args.ip_num * num_ports * num_scans;
    result = (results *)malloc(res_size * sizeof(results));
    int res_index = 0;

    get_local_ip(source_ip);

    pqueue = init_queue();  

    // init task queue
    for (i = 0; i < ps_args.ip_num; i++) {
        for (port = 0; port < PORT_NUM; port++) {
            if (ps_args.ports[port] == 1) {
                enqueue(pqueue, ps_args.ip_addr[i], port);
            }
        }
    }
    pthread_mutex_init(&scan_mutex, NULL);
    pthread_mutex_init(&result_mutex, NULL);

    printf("Scanning...\n");
    gettimeofday(&start, NULL);
    pthread_t thread[ps_args.threads];
    int thread_id[ps_args.threads]; // used for debug
    int id;
    for (id = 0; id < ps_args.threads; id++) {
        thread_id[id] = id;
        pthread_create(&thread[id], NULL, thread_func, (void *)&thread_id[id]);
    }

    for (i = 0; i < ps_args.threads; i++) {
        thread_res = pthread_join(thread[i], &retval);
        if (thread_res) {
            // printf("pthread_join() failed. Error num: %d. Error: %s. \n", errno, strerror(errno));
            exit(thread_res);
        }
    }
    
    gettimeofday(&end, NULL);

    int sec;
    int usec;

    // time cost
    if (end.tv_usec < start.tv_usec) {
        usec = end.tv_usec - start.tv_usec + 1000000;
        end.tv_sec--;
    }
    else {
        usec = end.tv_usec - start.tv_usec;
    }
    sec = end.tv_sec - start.tv_sec;
    printf("Scan took %d.%d seconds. \n", sec, usec);

    for (i = 0; i < ps_args.ip_num; i++) {
        printf("IP address: %s\n", ps_args.ip_addr[i]);
        printf("Port\tService Name (if applicable)\tScan Type\tResults\n");
        printf("--------------------------------------------------------------------------------------------------\n");
        print_res(ps_args.ip_addr[i], res_size);
    }

    free_mem(&ps_args);
    free_queue(pqueue);

    return 0;
}
