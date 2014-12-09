#ifndef _PS_SETUP_H_
#define _PS_SETUP_H_

#include "ps_setup.h"
#include "ps_lib.h"

struct qnode {
    char ip_addr[IP_ADDR_LEN];
    int port;
    // int scan_type;
    struct qnode *next;
};

struct port_queue {
    struct qnode *head;
    struct qnode *tail;
    int size;
};

/*
 * usage(FILE *file) -> void
 *
 * print the usage of this program to the file stream file.
 */
void usage(FILE *file);

/*
 * parse_args(ps_args_t *ps_args, int argc, char *argv[]) -> void
 *
 * parse arguments.
 */
void parse_args(ps_args_t *ps_args, int argc, char *argv[]);

struct port_queue *init_queue();

int is_empty(struct port_queue *pqueue);

void free_queue(struct port_queue *pqueue);

void clear_queue(struct port_queue *pqueue);

void enqueue(struct port_queue *pqueue, char *ip_addr, int port);

void dequeue(struct port_queue *pqueue, char *ip_addr, int *port);

#endif
