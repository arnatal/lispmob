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


#include "rtr_external.h"

#define BUFLEN 512

#define RUNNING_ON_RTR



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


int nat_aware = FALSE;
int behind_nat = UNKNOWN;


/*
 *      socket data
 */

int v4_fordward_fd = 0;


lisp_addr_t global_mn_rloc;
lisp_addr_t local_mn_rloc;
unsigned int global_mn_port;
//unsigned int local_mn_port;


void error(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}



build_fordward_socket()
{

    struct protoent *proto;
    struct sockaddr_in v4;
    int tr = 1;

    if ((proto = getprotobyname("UDP")) == NULL) {
        syslog(LOG_DAEMON, "getprotobyname: %s", strerror(errno));
        return (0);
    }

    /*
     *  build the v4_receive_fd, and make the port reusable
     */

    if ((v4_fordward_fd = socket(AF_INET, SOCK_DGRAM, proto->p_proto)) < 0) {
        syslog(LOG_DAEMON, "socket (v4): %s", strerror(errno));
        return (0);
    }

    if (setsockopt(v4_fordward_fd,
                   SOL_SOCKET, SO_REUSEADDR, &tr, sizeof(int)) == -1) {
        syslog(LOG_DAEMON, "setsockopt SO_REUSEADDR (v4): %s",
               strerror(errno));
        return (0);
    }


    memset(&v4, 0, sizeof(v4)); /* be sure */
    v4.sin_port = htons(LISP_DATA_PORT);
    v4.sin_family = AF_INET;
    v4.sin_addr.s_addr = INADDR_ANY;

    if (bind(v4_fordward_fd, (struct sockaddr *) &v4, sizeof(v4)) == -1) {
        syslog(LOG_DAEMON, "bind (v4): %s", strerror(errno));
        return (0);
    }

    return (1);

}


int main(int argc, char **argv)
{

    int max_fd;
    fd_set readfds;
    time_t curr, prev;          //Modified by acabello

    struct sockaddr_in si_local, si_remote;
    int s;
    int slen;
    char buf[BUFLEN];

    int fromlen4 = sizeof(struct sockaddr_in);
    struct sockaddr_in s4;
    uint8_t packet[MAX_IP_PACKET];

    unsigned int orig_from_port;
    lisp_addr_t orig_from_addr;

    unsigned int rewrited_from_port;
    lisp_addr_t rewrited_from_addr;

    unsigned int rewrited_dest_port;
    lisp_addr_t rewrited_dest_addr;

    unsigned int rtr_port;
    lisp_addr_t rtr_addr;

	unsigned int len_pkt;


    rtr_addr = inet_lisp_addr(RTR_TEST_RLOC, RTR_TEST_RLOC_AFI);
    rtr_port = LISP_DATA_PORT;

    /*
     *  calculate the max_fd for select. Is there a better way
     *  to do this?
     */

    /*
     * now build the v4/v6 receive sockets
     */

    if (build_receive_sockets() == 0)
        exit(EXIT_FAILURE);

    if (build_fordward_socket() == 0)
        exit(EXIT_FAILURE);


    max_fd =
        (v4_receive_fd > v6_receive_fd) ? v4_receive_fd : v6_receive_fd;
    max_fd = (max_fd > v4_fordward_fd) ? max_fd : v4_fordward_fd;

    for (EVER) {
        FD_ZERO(&readfds);
        FD_SET(v4_receive_fd, &readfds);
        FD_SET(v6_receive_fd, &readfds);
        FD_SET(v4_fordward_fd, &readfds);

        if (have_input(max_fd, &readfds) == -1)
            break;              /* news is bad */
        if (FD_ISSET(v4_receive_fd, &readfds))
            process_lisp_msg(v4_receive_fd, AF_INET);
        if (FD_ISSET(v6_receive_fd, &readfds))
            process_lisp_msg(v6_receive_fd, AF_INET6);
        if (FD_ISSET(v4_fordward_fd, &readfds)) {
            printf("## DATA PACKET RECEIVED ##\n");
            memset(&s4, 0, sizeof(struct sockaddr_in));
            len_pkt = recvfrom(v4_fordward_fd,
                         packet,
                         MAX_IP_PACKET,
                         0, (struct sockaddr *) &s4, &fromlen4);
			if (len_pkt< 0) {
                syslog(LOG_DAEMON, "recvfrom (v4): %s", strerror(errno));
                return (0);
            }

            get_source_address_and_port((struct sockaddr *) &s4,
                                        &orig_from_addr,
                                        (uint16_t *) & orig_from_port);


            rewrited_from_port = LISP_DATA_PORT;
            rewrited_from_addr =
                inet_lisp_addr(RTR_TEST_RLOC, RTR_TEST_RLOC_AFI);

            /* Packet comes from the MN */
            if (TRUE ==
                compare_lisp_addresses(&orig_from_addr, &global_mn_rloc)) {
                rewrited_dest_addr = inet_lisp_addr(PEER_ADD, AF_INET); //hardcoded destination
                rewrited_dest_port = LISP_DATA_PORT;
                /* Packet goes to the MN */
            } else {
                rewrited_dest_addr = global_mn_rloc;
                rewrited_dest_port = global_mn_port;
            }

            send_packet(packet,
                        len_pkt,
                        &rewrited_from_addr,
                        rewrited_from_port,
                        &rewrited_dest_addr, rewrited_dest_port);
        }
    }
}


/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
