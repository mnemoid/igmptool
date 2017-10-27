/*
 * igmptool.h
 *
 *  Created on: Oct 25, 2017
 *      Author: Vladimir Lutsenko
 *
 *  This file is part of igmptool.
 *
 *    igmptool is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *
 *    igmptool is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with igmptool.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef IGMPTOOL_H_
#define IGMPTOOL_H_

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/igmp.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include "log.h"

#define PROG_NAME				"igmptool"
#define PROG_VERSION			"0.2.0"
#define PROG_COPYRIGHT			"2017 Vladimir Lutsenko"

#define DEFAULT_IF_NAME			"eth0"
#define DEFAULT_DST_ADDR		"224.0.0.1"
#define DEFAULT_SRC_ADDR		"192.168.88.3"
#define DEFAULT_GROUP			"0.0.0.0"
#define DEFAULT_IGMP_VER		2
#define DEFAULT_QUERY_INTERVAL	125
#define DEFAULT_RESP_INTERVAL	100
#define IPV4_HDR_LEN			20
#define IGMP_HDR_LEN			8
#define SEND_BUFFER_LEN			64
#define LOG_FILE_PATH			"/var/log/igmptool/igmptool.log"
#define DEFAULT_LOG_LEVEL		5 /* LOG_NOTICE */
#define PID_FILE_PATH			"/var/run/igmptool.pid"
#define DESC_STRLEN				256

#define FLAG_INTERACTIVE		1

int pid_fd = 0;						/* PID file descriptor */
volatile sig_atomic_t sig_code = 0; /* Signal code */

static struct {
	unsigned int igmp_version;		/* IGMP Version */
	char *log_file_path;			/* Log file path */
	char *pid_file_path;			/* Path to PID file */
	char *if_name;					/* Network interface for binding */
	unsigned int query_interval;	/* IGMP query interval */
	uint8_t resp_interval;			/* Max Response Interval */
	unsigned int flags;				/* Flags as defined in FLAG_* */
	int loglevel;					/* Log level */
} main_cfg;

void signal_handler(int);
uint16_t checksum (uint16_t *, int);
int init_send_socket(void);
int init_recv_socket(void);
int get_hwaddr(int, uint8_t *);
size_t prepare_send_buffer(char *, int, const char *, uint8_t);
int check_mac(char *, uint8_t *);
int parse_received_packet(const char *, ssize_t);
void querier_loop(void);
pid_t daemonize(void);
void cleanup_and_exit(int);
void print_usage(void);

#endif /* IGMPTOOL_H_ */
