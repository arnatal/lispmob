//modified by arnatal

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <sys/timerfd.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include <signal.h>
#include <errno.h>
#include <syslog.h>
#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/timerfd.h>
#include <net/if.h>


#include "lispd_external.h"


#define BUFLEN             512

//modified by arnatal
/* Temporal. For NAT traversal testing implementation purpose. 
 * To be removed when it's done
 */ 
#define RTR_TEST_RLOC	"192.168.56.102"
#define RTR_TEST_RLOC_AFI	AF_INET


//modified by arnatal
// Temporal NAT traversal testing implementation purpose. 
// To be removed when it's done
#define EID_PREFIX "192.168.7.1"        //"123.213.111.178"
#define EID_AFI AF_INET
#define RLOC_PREFIX "123.123.123.123"
#define RLOC_AFI AF_INET
#define SERVER_ADD "192.168.56.102"
#define SERVER_AFI AF_INET
#define SOURCE_ADDR "192.168.56.101"


void event_loop(void);
void signal_handler(int);
void callback_elt(datacache_elt_t *);

/*
 *      global (more or less) vars
 *
 */

/*
 *      database and map cache
 */

lispd_database_t *lispd_database = NULL;
lispd_map_cache_t *lispd_map_cache = NULL;

/*
 *      next gen database
 */

patricia_tree_t *AF4_database = NULL;
patricia_tree_t *AF6_database = NULL;

/*
 *      data cache
 */

datacache_t *datacache;

/*
 *      config paramaters
 */

lispd_addr_list_t *map_resolvers = 0;
lispd_addr_list_t *proxy_etrs = 0;
lispd_addr_list_t *proxy_itrs = 0;
lispd_map_server_list_t *map_servers = 0;
char *config_file = "lispd.conf";
char *map_resolver = NULL;
char *map_server = NULL;
char *proxy_etr = NULL;
char *proxy_itr = NULL;
int debug = 0;
int daemonize = 0;
int map_request_retries = DEFAULT_MAP_REQUEST_RETRIES;
int control_port = LISP_CONTROL_PORT;
uint32_t iseed = 0;             /* initial random number generator */
/*
 *      various globals
 */

char msg[128];                  /* syslog msg buffer */
pid_t pid = 0;                  /* child pid */
pid_t sid = 0;
/*
 *      sockets (fds)
 */
int v6_receive_fd = 0;
int v4_receive_fd = 0;
int netlink_fd = 0;
fd_set readfds;
struct sockaddr_nl dst_addr;
struct sockaddr_nl src_addr;
nlsock_handle nlh;
/*
 *      timers (fds)
 */
int map_register_timer_fd = 0;

/* 
 * Interface on which control messages
 * are sent
 */
iface_list_elt *ctrl_iface = NULL;
//lispd_addr_t source_rloc;
lisp_addr_t source_rloc;


int NATaware = FALSE;
int behindNAT = UNKNOWN;


void error(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}




int main(int argc, char **argv)
{
    struct sockaddr_in si_server;
    int port, s, i, slen = sizeof(si_server);
    char buf[BUFLEN] = "";
    char *srv_addr;
    fd_set readfds;
    struct timeval tv;
    int ret;

    int max_fd;

    lisp_addr_t source_address;

    lisp_addr_t eid_prefix;
    eid_prefix = inet_lisp_addr(EID_PREFIX, EID_AFI);


//~ typedef struct {
    //~ lisp_addr_t     eid_prefix;
    //~ uint16_t        eid_prefix_length;
    //~ uint16_t        eid_prefix_afi; 
    //~ lisp_addr_t     locator;
    //~ uint16_t        locator_afi;
    //~ uint8_t         locator_type:2;
    //~ uint8_t         reserved:6;
    //~ char *          locator_name;
    //~ uint8_t         priority;
    //~ uint8_t         weight;
    //~ uint8_t         mpriority;
    //~ uint8_t         mweight;
//~ } lispd_db_entry_t;

    lispd_db_entry_t *db_entry;

    db_entry = (lispd_db_entry_t *) malloc(sizeof(lispd_db_entry_t));

    db_entry->eid_prefix = inet_lisp_addr(EID_PREFIX, EID_AFI);
    db_entry->eid_prefix_length = get_addr_len(EID_AFI);
    //db_entry->eid_prefix_afi=EID_AFI;
    db_entry->locator = inet_lisp_addr(RLOC_PREFIX, RLOC_AFI);
    //db_entry->locator_afi=RLOC_AFI;
    db_entry->locator_type = 0;
    db_entry->priority = 1;
    db_entry->weight = 2;
    db_entry->mpriority = 3;
    db_entry->mweight = 4;



//~ typedef struct lispd_locator_chain_elt_t_ {
    //~ lispd_db_entry_t                    *db_entry;
    //~ char                                *locator_name;
    //~ struct lispd_locator_chain_elt_t_   *next;
//~ } lispd_locator_chain_elt_t;

    lispd_locator_chain_elt_t *locator_chain_elt;

    locator_chain_elt =
        (lispd_locator_chain_elt_t *)
        malloc(sizeof(lispd_locator_chain_elt_t));

    locator_chain_elt->db_entry = db_entry;
    locator_chain_elt->locator_name = "locatorname";
    locator_chain_elt->next = NULL;



//~ typedef struct {                        /* chain per eid-prefix/len/afi */
    //~ int         mrp_len;                /* map register packet length */
    //~ uint32_t    timer;                  /* send map_register w timer expires */
    //~ ushort      locator_count;          /* number of mappings, 1 locator/per */
    //~ lisp_addr_t eid_prefix;             /* eid_prefix for this chain */
    //~ uint8_t     eid_prefix_length;      /* eid_prefix_length for this chain */
    //~ uint16_t    eid_prefix_afi;         /* eid_prefix_afi for this chain */
    //~ char        *eid_name;              /* eid_prefix_afi for this chain */
    //~ uint8_t     has_dynamic_locators:1; /* append dynamic/fqdn to front */
    //~ uint8_t     has_fqdn_locators:1;
    //~ uint8_t     reserved:6; 
    //~ lispd_locator_chain_elt_t *head;    /* first entry in chain */
    //~ lispd_locator_chain_elt_t *tail;    /* last entry in chain */
//~ } lispd_locator_chain_t;

    lispd_locator_chain_t *locator_chain;

    locator_chain =
        (lispd_locator_chain_t *) malloc(sizeof(lispd_locator_chain_t));

    locator_chain->mrp_len = 0;
    locator_chain->timer = 13;
    locator_chain->locator_count = 1;
    locator_chain->mrp_len = 0;
    locator_chain->eid_prefix = eid_prefix;
    locator_chain->eid_prefix_length = 32;
    //locator_chain->eid_prefix_afi=EID_AFI;
    locator_chain->eid_name = "eidname";

    locator_chain->head = locator_chain_elt;
    locator_chain->tail = locator_chain_elt;


    lispd_pkt_map_register_t *map_register_pkt;





    //~ typedef struct  {
    //~ lisp_addr_t address;
    //~ uint16_t    afi;
    //~ } lispd_addr_t;

    lisp_addr_t ms_address;

    ms_address = inet_lisp_addr(SERVER_ADD, SERVER_AFI);
    //ms_address.afi=SERVER_AFI;


    //~ typedef struct _lispd_map_server_list_t {
    //~ lispd_addr_t                    *address;
    //~ uint8_t                         key_type;
    //~ char                            *key;
    //~ uint8_t                         proxy_reply;
    //~ uint8_t                         verify;
    //~ struct _lispd_map_server_list_t *next;
    //~ } lispd_map_server_list_t;


    lispd_map_server_list_t *map_server_list;

    map_server_list =
        (lispd_map_server_list_t *)
        malloc(sizeof(lispd_map_server_list_t));


    map_server_list->address = &ms_address;
    map_server_list->key_type = KEY_TYPE;
    map_server_list->key = KEY;
    map_server_list->proxy_reply = 1;

    map_server_list->next = NULL;


    lisp_addr_t vbox1 = inet_lisp_addr("192.168.56.101", AF_INET);
    lisp_addr_t vbox2 = inet_lisp_addr("192.168.56.102", AF_INET);
    lisp_addr_t vbox3 = inet_lisp_addr("192.168.56.103", AF_INET);


    //source_address = inet_lisp_addr(SOURCE_ADDR,AF_INET);
    source_address = inet_lisp_addr(SERVER_ADD, AF_INET);

    // Data socket

    srv_addr = SERVER_ADD;

    if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        error("socket");
    }

    memset((char *) &si_server, 0, sizeof(si_server));
    si_server.sin_family = AF_INET;
    si_server.sin_port = htons(LISP_DATA_PORT);
    if (inet_aton(srv_addr, &si_server.sin_addr) == 0) {
        fprintf(stderr, "inet_aton() failed\n");
        exit(EXIT_FAILURE);
    }

    printf("Sending ECM Map Register\n");


    build_and_send_ecm_map_register(locator_chain, &(vbox1), &vbox1, LISP_CONTROL_PORT, LISP_CONTROL_PORT, &(vbox1), &(vbox2),  //source addres is the address of the client
                                    LISP_CONTROL_PORT,
                                    LISP_CONTROL_PORT,
                                    map_server_list->key_type,
                                    map_server_list->key);




    if (locator_chain) {
        /*
           printf("Sending Map Register\n");
           build_and_send_map_register(locator_chain,map_server_list,&vbox1);


           printf("Sending Info Request\n");
           build_and_send_info_request(1,
           map_server_list->key_type,
           map_server_list->key,
           DEFAULT_INFO_REQUEST_TIMEOUT,
           locator_chain->eid_prefix_length,
           &(locator_chain->eid_prefix),
           &(vbox1),
           LISP_CONTROL_PORT,
           &(vbox2),
           LISP_CONTROL_PORT);

         */
        //build_and_send_info_request(locator_chain,map_server_list,SOURCE_ADDR);

        /*

           sprintf(buf, "DATA PACKET");

           slen = sizeof(si_server);
           if (sendto(s, buf, BUFLEN, 0, (struct sockaddr *)&si_server, slen)==-1)
           {
           error("sendto()");
           }
         */
    }

    close(s);

    free(map_server_list);
    free(locator_chain);
    free(locator_chain_elt);
    free(db_entry);


    int fromlen4 = sizeof(struct sockaddr_in);
    struct sockaddr_in s4;
    uint8_t packet[MAX_IP_PACKET];

    /*
     *  calculate the max_fd for select. Is there a better way
     *  to do this?
     */

    /*
     * now build the v4/v6 receive sockets
     */

    if (build_receive_sockets() == 0)
        exit(EXIT_FAILURE);


    max_fd =
        (v4_receive_fd > v6_receive_fd) ? v4_receive_fd : v6_receive_fd;


    printf("Waiting for packets....\n");

    for (EVER) {
        FD_ZERO(&readfds);
        FD_SET(v4_receive_fd, &readfds);
        FD_SET(v6_receive_fd, &readfds);


        if (have_input(max_fd, &readfds) == -1)
            break;              /* news is bad */
        if (FD_ISSET(v4_receive_fd, &readfds))
            process_lisp_msg(v4_receive_fd, AF_INET);
        if (FD_ISSET(v6_receive_fd, &readfds))
            process_lisp_msg(v6_receive_fd, AF_INET6);

    }


    return (0);
}

////


/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
