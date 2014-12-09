#include "ps_setup.h"
#include "ps_lib.h"

/*
 * usage(FILE *file) -> void
 *
 * print the usage of this program to the file stream file
 */
void usage(FILE *file) {
    if (file == NULL) {
        file = stdout;
    }

    fprintf(file,
          "./portScanner [option1, ..., optionN]\n"
          "    --help                                \tPrint this help screen\n"
          "    --ports <ports>                       \tSet the ports to scan(default: 1-1024)\n"
          "    --ip <IP address>                     \tSet IP address to scan\n"
          "    --prefix <IP prefix>                  \tSet IP prefix to scan\n"
          "    --file <file containing IP addresses> \tRead IP addresses from file\n"
          "    --speedup <number of threads>         \tSet how many threads to use\n"
          "    --scan <scan types>                   \tSet scan types(default: all scans)\n");
}

/*
 * _parse_ports(ps_args_t *ps_args, char *ports) -> void
 *
 * Parse port arguments and assign all ports to ps_args
 */
void _parse_ports(ps_args_t *ps_args, char *ports) {
    int i;
    memset(ps_args->ports, 0, PORT_NUM * sizeof(int));

    int idx_1 = 0;
    int idx_2 = 0;
    int length = strlen(ports);

    for (i = 0; i < length; i++) {
        if (ports[i] >= '0' && ports[i] <= '9') {
            idx_1 *= 10;
            idx_1 = idx_1 + ports[i] - '0';
        }
        else if (ports[i] == ',') {
            ps_args->ports[idx_1] = 1;
            idx_1 = 0;
        }
        else if (ports[i] == '-') {
            i++;
            int j;
            while (i < length && ports[i] >= '0' && ports[i] <= '9') {
                idx_2 *= 10;
                idx_2 = idx_2 + ports[i] - '0';
                i++;
            }

            // set all ports from idx_1 to idx_2
            for (j = idx_1; j <= idx_2; j++) {
                ps_args->ports[j] = 1;
            }
            idx_1 = 0;
            idx_2 = 0;
        }
    }

    if (idx_1 != 0) {
        ps_args->ports[idx_1] = 1;
    }
}

/*
 * _parse_ip(ps_args_t *ps_args, char *ip) -> void
 *
 * Parse ip addresses and store them into global arguments. This function is also called
 * when parsing ip file or parsing ip prefix.
 */
void _parse_ip(ps_args_t *ps_args, char *ip) {
    int i;
    for (i = 0; i < ps_args->ip_num; i++) {
        if (!memcmp(ip, ps_args->ip_addr[i], IP_ADDR_LEN)) {
            // already contains this ip
            printf("ip idx: %d\n", i);
            printf("ip: %s\n", ip);
            printf("ps_args: %s\n", ps_args->ip_addr[i]);
            return;
        }
    }

    ps_args->ip_addr[ps_args->ip_num] = (char *)malloc(IP_ADDR_LEN * sizeof(char));
    memcpy(ps_args->ip_addr[ps_args->ip_num], ip, IP_ADDR_LEN);
    ps_args->ip_num++;
}

/*
 * _parse_file(ps_args_t *ps_args, char *filename) -> void
 *
 * Read file which contains ip addresses, then call _parse_ip() function to keep them
 * in arguments structure.
 */
void _parse_file(ps_args_t *ps_args, char *filename) {
    FILE *ip_file = fopen(filename, "r");
    if (ip_file == NULL) {
        fprintf(stderr, "Open file failed. \n");
        return;
    }

    size_t len = 0;
    char *ip = NULL;

    while (getline(&ip, &len, ip_file) != -1) {
        ip[strlen(ip) - 1] = '\0'; // add a '\0' to avoid weird characters
        _parse_ip(ps_args, ip);
    }

    free(ip);
    fclose(ip_file);
}

/*
 * _parse_scan(ps_args_t *ps_args, char *optarg) -> void
 *
 * Parse input scan types.
 */
void _parse_scan(ps_args_t *ps_args, char *optarg) {
    char type[5];
    memset(type, '\0', 5);
    memset(ps_args->scan_types, 0, 6 * sizeof(int));

    // since the length of optarg is only the length of the first type
    // do infinite loop until reading unknown string
    while (1) {
        memcpy(type, optarg, 5);
        if (!strcmp(type, "SYN")) {
            ps_args->scan_types[SYN] = 1;
        }
        else if (!strcmp(type, "NULL")) {
            ps_args->scan_types[NUL] = 1;
        }
        else if (!strcmp(type, "FIN")) {
            ps_args->scan_types[FIN] = 1;
        }
        else if (!strcmp(type, "XMAS")) {
            ps_args->scan_types[XMAS] = 1;
        }
        else if (!strcmp(type, "ACK")) {
            ps_args->scan_types[ACK] = 1;
        }
        else if (!strcmp(type, "UDP")) {
            ps_args->scan_types[UDP] = 1;
        }
        else {
            break;
        }
        optarg += strlen(type);
        optarg++;
        memset(type, '\0', 5);
    }

}

/*
 * _parse_prefix(ps_args_t *ps_args, char *optarg) -> void
 *
 * Parse ip addresses based on given prefix. Then call _parse_ip() function.
 */
void _parse_prefix(ps_args_t *ps_args, char *optarg) {
    char ip[IP_ADDR_LEN];
    // split input string into two parts: ip address and fixed length
    char *ip_temp = strtok(optarg, "/");
    char *match = strtok(NULL, "/");
    int padding = 32 - atoi(match);
    int padding_max = 1;
    u_int32_t pattern = 0xffffffff;

    // set the bit of fixed position to be 1, others to be 0
    // and determine how many ip addresses we need to deal with
    int i;
    for (i = 0; i < padding; i++) {
        pattern <<= 1;
        padding_max *= 2;
    }

    memcpy(ip, ip_temp, strlen(ip_temp));
    ip[strlen(ip_temp)] = '\0'; // padding '\0'

    struct in_addr ip_addr;
    inet_aton(ip, &ip_addr);

    u_int32_t ip_another = htonl(ip_addr.s_addr);
    ip_another &= pattern;

    for (i = 0; i < padding_max; i++) {
        ip_addr.s_addr = ntohl(ip_another);
        char *res = inet_ntoa(ip_addr);
        _parse_ip(ps_args, res);
        ip_another++;
    }
}

/*
 * parse_args(ps_args_t *ps_args, int argc, char *argv[]) -> void
 *
 * parse arguments.
 */
void parse_args(ps_args_t *ps_args, int argc, char *argv[]) {
    int ch; //ch for each flag
    char filename[FILE_NAME_MAX]; // latent file name
    char ip[IP_ADDR_LEN];

    // Set all ports to be 1(by default)
    memset(ps_args->ports, 0, PORT_NUM * sizeof(int));
    int i;
    for (i = 0; i <= 1024; i++) {
        ps_args->ports[i] = 1;
    }
    ps_args->ports[0] = -1; // 0 position not in use

    ps_args->ip_addr = (char **)malloc(1024 * sizeof(char));
    ps_args->ip_num = 0; // initially there's no ip info
    memset(ip, '\0', IP_ADDR_LEN);

    ps_args->threads = 1; // default: 1

    // Scan all types by default
    for (i = 0; i < 6; i++) {
        ps_args->scan_types[i] = 1;
    }

    int option_idx = 0;
    while ((ch = getopt_long(argc, argv, "hp:i:r:f:s:c", long_options, &option_idx)) != -1) {
        switch(ch) {
            case 'h': // help screen
                usage(stdout);
                exit(0);
                break;
            case 'p': // ports
                _parse_ports(ps_args, optarg);
                break;
            case 'i': // IP address
                memcpy(ip, optarg, strlen(optarg));
                _parse_ip(ps_args, ip);
                break;
            case 'r': // prefix
                _parse_prefix(ps_args, optarg);
                break;
            case 'f': // file
                memcpy(filename, optarg, FILE_NAME_MAX);
                _parse_file(ps_args, filename);
                break;
            case 's': // speedup
                ps_args->threads = atoi(optarg);
                break;
            case 'c': // scan
                _parse_scan(ps_args, optarg);
                break;
            default:
                usage(stdout);
                exit(0);
                break;
        }
    }
/*
    // milestone1 test outputs
    printf("IP addresses: \n");
    for (i = 0; i < ps_args->ip_num; i++) {
        printf("%s\n", ps_args->ip_addr[i]);
    }
    printf("\nPorts: \n");
    for (i = 0; i < PORT_NUM; i++) {
        if (ps_args->ports[i] == 1) {
            printf("%d ", i);
        }
    }
    printf("\n");
    printf("\nScan types: \n");
    if (ps_args->scan_types[SYN] == 1) {
        printf("SYN\n");
    }
    if (ps_args->scan_types[NUL] == 1) {
        printf("NULL\n");
    }
    if (ps_args->scan_types[FIN] == 1) {
        printf("FIN\n");
    }
    if (ps_args->scan_types[XMAS] == 1) {
        printf("XMAS\n");
    }
    if (ps_args->scan_types[ACK] == 1) {
        printf("ACK\n");
    }
    if (ps_args->scan_types[UDP] == 1) {
        printf("UDP\n");
    }
    printf("\n");

    printf("Threads: %d\n", ps_args->threads);
*/
}

struct port_queue *init_queue() {
    struct port_queue *pqueue = (struct port_queue *)malloc(sizeof(struct port_queue));
    if (pqueue != NULL) {
        pqueue->head = NULL;
        pqueue->tail = NULL;
        pqueue->size = 0;
    }
    return pqueue;
}

int is_empty(struct port_queue *pqueue) {
    if (pqueue->head == NULL && pqueue->tail == NULL && pqueue->size == 0) {
        return 1;
    }
    else {
        return 0;
    }
}

void free_queue(struct port_queue *pqueue) {
    if (is_empty(pqueue) == 0) {
        clear_queue(pqueue);
    }
    free(pqueue);
}

void clear_queue(struct port_queue *pqueue) {
    while (is_empty(pqueue) == 0) {
        dequeue(pqueue, NULL, NULL);
    }
}

void enqueue(struct port_queue *pqueue, char *ip_addr, int port) {
    struct qnode *new_node = (struct qnode *)malloc(sizeof(struct qnode));
    if (new_node != NULL) {
        strcpy(new_node->ip_addr, ip_addr);
        new_node->port = port;
        // new_node->scan_type = scan_type;
        new_node->next = NULL;

        if (is_empty(pqueue)) {
            pqueue->head = new_node;
        }
        else {
            pqueue->tail->next = new_node;
        }
        pqueue->tail = new_node;
        pqueue->size++;
    }
}

void dequeue(struct port_queue *pqueue, char *ip_addr, int *port) {
    struct qnode *node = pqueue->head;
    if (is_empty(pqueue) == 0 && node != NULL) {
        pqueue->size--;
        pqueue->head = node->next;
        if (ip_addr != NULL && port != NULL) {
            strcpy(ip_addr, node->ip_addr);
            *port = node->port;
            // *scan_type = node->scan_type;
        }
        free(node);
        if (pqueue->size == 0) {
            pqueue->tail = NULL;
        }
    }
    //return pqueue->head;
}
