/*
 * lispd.c 
 *
 * This file is part of LISP Mobile Node Implementation.
 * lispd Implementation
 * 
 * Copyright (C) 2011 Cisco Systems, Inc, 2011. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Please send any bug reports or fixes you make to the email address(es):
 *    LISP-MN developers <devel@lispmob.org>
 *
 * Written or modified by:
 *    David Meyer       <dmm@cisco.com>
 *    Preethi Natarajan <prenatar@cisco.com>
 *    Albert Cabellos   <acabello@ac.upc.edu>
 *    Lorand Jakab      <ljakab@ac.upc.edu>
 *    Alberto Rodriguez Natal <arnatal@ac.upc.edu>
 *
 */


#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
//#include <sys/timerfd.h>
#include <netinet/in.h>
#include <net/if.h>
#include "lispd.h"
#include "lispd_config.h"
#include "lispd_iface_list.h"
#include "lispd_iface_mgmt.h"
#include "lispd_input.h"
#include "lispd_lib.h"
#include "lispd_local_db.h"
#include "lispd_log.h"
#include "lispd_map_cache_db.h"
#include "lispd_map_register.h"
#include "lispd_map_request.h"
#include "lispd_output.h"
#include "lispd_smr.h"
#include "lispd_sockets.h"
#include "lispd_timers.h"
#include "lispd_tun.h"


void event_loop();
void signal_handler(int);
void exit_cleanup(void);



/*
 *      config paramaters
 */

lispd_addr_list_t          *map_resolvers   = NULL;
lispd_addr_list_t          *proxy_itrs      = NULL;
lispd_map_cache_entry      *proxy_etrs      = NULL;
lispd_map_server_list_t    *map_servers     = NULL;
char    *config_file                        = NULL;
int      debug_level                        = 0;
int      default_rloc_afi                   = -1;
int      daemonize                          = FALSE;
int      map_request_retries                = DEFAULT_MAP_REQUEST_RETRIES;
int      control_port                       = LISP_CONTROL_PORT;
uint32_t iseed                              = 0;  /* initial random number generator */
int      total_mappings                     = 0;
/*
 *      various globals
 */

char   msg[128];                                /* syslog msg buffer */
pid_t  pid                                  = 0;    /* child pid */
pid_t  sid                                  = 0;
/*
 *      sockets (fds)
 */
int     ipv4_data_input_fd                  = 0;
int     ipv6_data_input_fd                  = 0;
int     ipv4_control_input_fd               = 0;
int     ipv6_control_input_fd               = 0;
int     netlink_fd                          = 0;
fd_set  readfds;
struct  sockaddr_nl dst_addr;
struct  sockaddr_nl src_addr;
nlsock_handle nlh;

/*
 *      timers (fds)
 */

int     timers_fd                       = 0;

#ifdef LISPMOBMH
/* timer to rate control smr's in multihoming scenarios */
int 	smr_timer_fd					= 0;
#endif


int main(int argc, char **argv) 
{
    lisp_addr_t *tun_v4_addr;
    lisp_addr_t *tun_v6_addr;
    char *tun_dev_name = TUN_IFACE_NAME;



#ifdef ROUTER
#ifdef OPENWRT
    lispd_log_msg(LISP_LOG_INFO,"LISPmob compiled for openWRT xTR\n");
#else
    lispd_log_msg(LISP_LOG_INFO,"LISPmob compiled for linux xTR\n");
#endif
#else
    lispd_log_msg(LISP_LOG_INFO,"LISPmob compiled for mobile node\n");
#endif


    /*
     *  Check for superuser privileges
     */

    if (geteuid()) {
        lispd_log_msg(LISP_LOG_INFO,"Running %s requires superuser privileges! Exiting...\n", LISPD);
        exit(EXIT_FAILURE);
    }

    /*
     *  Initialize the random number generator
     */

    iseed = (unsigned int) time (NULL);
    srandom(iseed);

    /*
     * Set up signal handlers
     */

    signal(SIGHUP,  signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGINT,  signal_handler);
    signal(SIGQUIT, signal_handler);


    /*
     *  set up databases
     */

    db_init();
    map_cache_init();


    /*
     *  Parse command line options
     */

    handle_lispd_command_line(argc, argv);


// REMEMBER TO CHECK THIS!!!
    add_interface("eth0");
    
    set_default_ctrl_ifaces();
    
    if (default_ctrl_iface_v4){
        ipv4_control_input_fd = open_control_input_socket(AF_INET);
    }
    if (default_ctrl_iface_v6){
        ipv6_control_input_fd = open_control_input_socket(AF_INET6);
    }

    printf("======== lispd running as LISPflow Map Server ========\n");

    
    lispd_log_msg(LISP_LOG_INFO,"LISPmob (0.3.2): 'lispd' started...");

    event_loop();

    lispd_log_msg(LISP_LOG_INFO, "Exiting...");         /* event_loop returned bad */
    closelog();
    return(0);
}

/*
 *      main event loop
 *
 *      should never return (in theory)
 */

void event_loop()
{
    int    max_fd;
    fd_set readfds;
    int    retval;
    
    /*
     *  calculate the max_fd for select.
     */
    
    max_fd = ipv4_data_input_fd;
    max_fd = (max_fd > ipv6_data_input_fd)      ? max_fd : ipv6_data_input_fd;
    max_fd = (max_fd > ipv4_control_input_fd)   ? max_fd : ipv4_control_input_fd;
    max_fd = (max_fd > ipv6_control_input_fd)   ? max_fd : ipv6_control_input_fd;
    max_fd = (max_fd > tun_receive_fd)          ? max_fd : tun_receive_fd;
    max_fd = (max_fd > timers_fd)               ? max_fd : timers_fd;
    max_fd = (max_fd > netlink_fd)              ? max_fd : netlink_fd;

    for (;;) {
        FD_ZERO(&readfds);
        FD_SET(ipv4_control_input_fd, &readfds);
        FD_SET(ipv6_control_input_fd, &readfds);

        retval = have_input(max_fd, &readfds);
        if (retval == -1) {
            break;           /* doom */
        }
        if (retval == BAD) {
            continue;        /* interrupted */
        }

        if (FD_ISSET(ipv4_control_input_fd, &readfds)) {
            lispd_log_msg(LISP_LOG_DEBUG_3,"Received IPv4 packet in the control input buffer (4342)");
            process_lisp_ctr_msg(ipv4_control_input_fd, AF_INET);
        }
        if (FD_ISSET(ipv6_control_input_fd, &readfds)) {
            lispd_log_msg(LISP_LOG_DEBUG_3,"Received IPv6 packet in the control input buffer (4342)");
            process_lisp_ctr_msg(ipv6_control_input_fd, AF_INET6);
        }
    }

    
}

/*
 *      signal_handler --
 *
 */

void signal_handler(int sig) {
    switch (sig) {
    case SIGHUP:
        /* TODO: SIGHUP should trigger reloading the configuration file */
        lispd_log_msg(LISP_LOG_DEBUG_1, "Received SIGHUP signal.");
        break;
    case SIGTERM:
        /* SIGTERM is the default signal sent by 'kill'. Exit cleanly */
        lispd_log_msg(LISP_LOG_DEBUG_1, "Received SIGTERM signal. Cleaning up...");
        exit_cleanup();
        break;
    case SIGINT:
        /* SIGINT is sent by pressing Ctrl-C. Exit cleanly */
        lispd_log_msg(LISP_LOG_DEBUG_1, "Terminal interrupt. Cleaning up...");
        exit_cleanup();
        break;
    default:
        lispd_log_msg(LISP_LOG_DEBUG_1,"Unhandled signal (%d)", sig);
        exit(EXIT_FAILURE);
    }
}

/*
 *  exit_cleanup()
 *
 *  Close opened sockets and file descriptors
 */

void exit_cleanup(void) {

    /* Close timer file descriptors */
    close(timers_fd);

    /* Close receive sockets */
    close(tun_receive_fd);
    close(ipv4_data_input_fd);
    close(ipv4_control_input_fd);

    /* Close syslog */

    exit(EXIT_SUCCESS);
}




/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
