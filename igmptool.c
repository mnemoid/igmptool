/*
 * igmptool.c
 *
 *  Created on: Sep 29, 2017
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

#include "igmptool.h"

/* Signal handler */
void signal_handler(int signal) {
	if(signal == SIGTERM)
		sig_code = signal;
	return;
}

/* Calculate checksum of array of 2-byte words in network order (big-endian).
 * Returns value in host's byte order. */
uint16_t checksum (uint16_t *addr, int len) {
	uint32_t sum = 0;

	// Sum of each 2-byte values
	while(len > 1) {
		sum += ntohs(*(addr++));
		len -= 2;
	}

	// Add partial block if available at the end of data
	if(len > 0) {
		sum += *(uint8_t *)addr;
	}

	// Sum lower 16 bits and upper 16 bits
	while(sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	// Return one's compliment of sum.
	return (uint16_t)(~sum);
}

/* Init and return descriptor to sending socket */
int init_send_socket(void) {
	int sendfd;
	int sock_optval = 1;
	struct ifreq ifr;

	/* Get socket descriptor */
	write_log(LOG_INFO, "Get socket descriptor");

	if((sendfd = socket(AF_INET, SOCK_RAW, IPPROTO_IGMP)) < 0) {
		write_log(LOG_EMERG, "socket() failed to create socket: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Set flag that tells that we are providing IPv4 header */
	write_log(LOG_INFO, "Set IP_HDRINCL flag");
	if(setsockopt(sendfd, IPPROTO_IP, IP_HDRINCL, &sock_optval, sizeof(sock_optval)) < 0) {
		write_log(LOG_EMERG, "setsockopt() failed to set socket option IP_HDRINCL: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Bind to specified interface */
	write_log(LOG_INFO, "Bind to interface %s", main_cfg.if_name);
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, main_cfg.if_name, sizeof(ifr.ifr_name));
	if(ioctl(sendfd, SIOCGIFINDEX, &ifr) < 0) {
		write_log(LOG_EMERG, "ioctl() failed to get index of interface: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if(setsockopt(sendfd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
		write_log(LOG_EMERG, "setsockopt() failed to set socket option SO_BINDTODEVICE: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	return sendfd;
}

/* Init and return descriptor to receiving socket */
int init_recv_socket(void) {
	int recvfd;
	struct ifreq ifr;

	if((recvfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
		write_log(LOG_EMERG, "socket() failed to create recv socket: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, main_cfg.if_name, sizeof(ifr.ifr_name));
	ioctl(recvfd, SIOCGIFFLAGS, &ifr);

	/* Put interface in promiscuous mode */
	ifr.ifr_flags |= IFF_PROMISC;
	if(ioctl(recvfd, SIOCSIFFLAGS, &ifr) < 0) {
		write_log(LOG_EMERG, "ioctl() failed to bind to specified interface: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	return recvfd;
}

/* Get MAC address of interface defined by sockfd and save it in array mac_addr */
int get_hwaddr(int sockfd, uint8_t *mac_addr) {
	struct ifreq ifr;

	write_log(LOG_DEBUG, "Get MAC address of receiving interface %s", main_cfg.if_name);
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, main_cfg.if_name, sizeof(ifr.ifr_name));

	if(ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
		write_log(LOG_EMERG, "ioctl() failed to get MAC address of interface: %s", strerror(errno));
		return -1;
	}

	memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, 6);

	write_log(LOG_INFO, "Interface %s MAC address: %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", main_cfg.if_name,
			mac_addr[0],
			mac_addr[1],
			mac_addr[2],
			mac_addr[3],
			mac_addr[4],
			mac_addr[5]);

	return 1;
}

size_t prepare_send_buffer(char *send_buffer, int sendfd, const char *dest_addr_str, uint8_t resp_interval) {
	size_t	packet_len = 0;
	struct ifreq ifr;
	struct sockaddr_in src_addr;
	struct ip iphdr;
	struct igmp igmphdr;

	/* Get source address */
	write_log(LOG_INFO, "Get IP address of interface %s", main_cfg.if_name);
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, main_cfg.if_name, sizeof(ifr.ifr_name));
	ifr.ifr_addr.sa_family = AF_INET;
	if(ioctl(sendfd, SIOCGIFADDR, &ifr) < 0) {
		write_log(LOG_EMERG, "ioctl() failed to get IP address of interface: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}
	src_addr.sin_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
	write_log(LOG_INFO, "Source IP address: %s", inet_ntoa(src_addr.sin_addr));

	/* Prepare packet's IPv4 header */
	write_log(LOG_INFO, "Prepare IPv4 header");

	memset(&iphdr, 0, sizeof(iphdr));
	iphdr.ip_v = 4;
	iphdr.ip_hl = IPV4_HDR_LEN / 4;
	iphdr.ip_tos = 0xc0;
	iphdr.ip_len = htons(IPV4_HDR_LEN + IGMP_HDR_LEN);
	iphdr.ip_id = htons(0);
	iphdr.ip_off = htons(0);
	iphdr.ip_ttl = 1;
	iphdr.ip_p = IPPROTO_IGMP;
	iphdr.ip_src = src_addr.sin_addr;
	inet_pton(AF_INET, dest_addr_str, &iphdr.ip_dst);
	iphdr.ip_sum = htons(checksum((uint16_t *)&iphdr, IPV4_HDR_LEN));

	/* IGMPv2 header */
	memset(&igmphdr, 0, sizeof(igmphdr));
	igmphdr.igmp_type = IGMP_MEMBERSHIP_QUERY;
	igmphdr.igmp_code = resp_interval;
	inet_pton(AF_INET, DEFAULT_GROUP, &igmphdr.igmp_group);
	igmphdr.igmp_cksum = 0;

	/* Copy IPv4 and IGMP headers to buffer */
	memcpy(send_buffer, &iphdr, IPV4_HDR_LEN);
	memcpy(send_buffer+IPV4_HDR_LEN, &igmphdr, IGMP_HDR_LEN);

	packet_len = IPV4_HDR_LEN + IGMP_HDR_LEN;

	igmphdr.igmp_cksum = htons(checksum((uint16_t *)send_buffer, packet_len));
	memcpy(send_buffer+IPV4_HDR_LEN, &igmphdr, IGMP_HDR_LEN);

	return packet_len;
}

/* Check MAC address. Return 0 if not IP protocol or MAC address is not our or multicast address. */
int check_mac(char *buffer, uint8_t *mac_addr) {
	struct ether_header *eth_hdr = (struct ether_header *) buffer;

	/* Drop if not IP protocol */
	if(ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) {
		return 0;
	}

	/* Drop if not our MAC address and not multicast address */
	if(strncmp((char *)mac_addr, (char *)eth_hdr->ether_dhost,6) != 0 && eth_hdr->ether_dhost[0] != 0x01) {
		return 0;
	}

	return 1;
}

int parse_received_packet(const char *buffer, ssize_t recv_packet_size) {
	uint16_t orig_chksum, calc_chksum;
	unsigned int payload_size;
	char temp_ip_hdr[60];
	char temp_payload[1500];
	char dst_addr_str[INET_ADDRSTRLEN];
	char src_addr_str[INET_ADDRSTRLEN];
	char grp_addr_str[INET_ADDRSTRLEN];
	char desc_str[DESC_STRLEN];
	struct ip *ip_hdr = (struct ip *)(buffer + sizeof(struct ether_header));
	struct igmp *igmp_hdr = (struct igmp *)(buffer+sizeof(struct ether_header)+ip_hdr->ip_hl*4);

	memcpy(temp_ip_hdr, ip_hdr, ip_hdr->ip_hl*4);

	orig_chksum = ntohs(ip_hdr->ip_sum);

	/* Set packet's checksum = 0 and calculate checksum; */
	temp_ip_hdr[10] = 0;
	temp_ip_hdr[11] = 0;
	calc_chksum = checksum ((uint16_t *)temp_ip_hdr, ip_hdr->ip_hl*4);

	if(calc_chksum != orig_chksum) {
		write_log(LOG_WARNING, "Received packet with bad checksum %04hx, (must be %04hx)", orig_chksum, calc_chksum);
		return -1;
	}

	/* Check for strange packets: 1 - packet length too small, 2 - IP version not = 4, 3 - IP header too small */
	if(ntohs(ip_hdr->ip_len) < 20 || ip_hdr->ip_v != 4 || ip_hdr->ip_hl < 5) {
		write_log(LOG_WARNING, "Received bad packet");
		return -1;
	}

	if(ip_hdr->ip_p != IPPROTO_IGMP) {
		return 0;
	}

	/* Check IGMP packet */
	if(recv_packet_size > 1500) {
		return -1;
	}

	payload_size = ntohs(ip_hdr->ip_len) - ip_hdr->ip_hl*4;
	memcpy(temp_payload, igmp_hdr, payload_size);

	orig_chksum = ntohs(igmp_hdr->igmp_cksum);
	temp_payload[2] = 0;
	temp_payload[3] = 0;
	calc_chksum = checksum((uint16_t *)temp_payload, payload_size);

	if(calc_chksum != orig_chksum) {
		write_log(LOG_WARNING, "Received IGMP data with bad checksum %04hx, (must be %04hx)", orig_chksum, calc_chksum);
		return -1;
	}

	switch(igmp_hdr->igmp_type) {
		case 0x11:
			if(igmp_hdr->igmp_group.s_addr == 0) {
				strncpy(desc_str, "v2 general query", DESC_STRLEN);
			}
			else {
				strncpy(desc_str, "v2 query", DESC_STRLEN);
			}
			break;
		case 0x12:
			strncpy(desc_str, "v1 report", DESC_STRLEN);
			break;
		case 0x16:
			strncpy(desc_str, "v2 report", DESC_STRLEN);
			break;
		case 0x17:
			strncpy(desc_str, "v2 leave", DESC_STRLEN);
			break;
		default:
			strncpy(desc_str, "unknown type", DESC_STRLEN);
	}

	/* Print packet data */
	inet_ntop(AF_INET, &ip_hdr->ip_src, src_addr_str, sizeof src_addr_str);
	inet_ntop(AF_INET, &ip_hdr->ip_dst, dst_addr_str, sizeof dst_addr_str);
	inet_ntop(AF_INET, &igmp_hdr->igmp_group, grp_addr_str, sizeof grp_addr_str);
	write_log(LOG_INFO, "IP %s > %s: (0x%02hhx) igmp %s %s", src_addr_str, dst_addr_str, igmp_hdr->igmp_type, desc_str, grp_addr_str);

	return 1;
}

void querier_loop(void) {
	int sendfd, recvfd, poll_res;
	char send_buffer[SEND_BUFFER_LEN];
	char recv_buffer[IP_MAXPACKET];
	char dest_addr_str[INET_ADDRSTRLEN];
	size_t	send_packet_size = 0;
	ssize_t recv_packet_size;
	uint8_t our_mac[6];
	struct sockaddr_in dest_addr;
	struct pollfd poll_fd;
	struct timeval current_time, prev_time, delta_time, query_time;
	struct sigaction sa;
	sigset_t sig_mask;

	/* Init destination address string with default value (224.0.0.1) */
	memset(&dest_addr, 0, sizeof(dest_addr));
	memset(dest_addr_str, 0, sizeof(dest_addr_str));
	strcpy(dest_addr_str, DEFAULT_DST_ADDR);

	/* Fill timeval structure using query interval vlaue from configuration */
	query_time.tv_sec = main_cfg.query_interval;
	query_time.tv_usec = 0;

	sendfd = init_send_socket();

	send_packet_size = prepare_send_buffer(send_buffer, sendfd, dest_addr_str, main_cfg.resp_interval);

	recvfd = init_recv_socket();

	get_hwaddr(recvfd, our_mac);

	/* Fill poll descriptor */
	poll_fd.fd = recvfd;
	poll_fd.events = POLLIN;
	poll_fd.revents = 0;

	/* Init and set signal handler */
	sigemptyset(&sig_mask);
	sigaddset(&sig_mask, SIGTERM);
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = signal_handler;
	sa.sa_mask = sig_mask;

	if(sigaction(SIGTERM, &sa, 0) == -1) {
		write_log(LOG_EMERG, "Error occurred while prepare signal handler! %s", strerror(errno));
		cleanup_and_exit(EXIT_FAILURE);
	}

	write_log(LOG_DEBUG, "Start loop");

	/* Main loop */
	while(1) {
		write_log(LOG_INFO, "Send general query (0.0.0.0) to interface %s", main_cfg.if_name);

		/* Set destination address */
		inet_pton(AF_INET, dest_addr_str, &dest_addr.sin_addr);

		/* Send packet */
		if(sendto(sendfd, send_buffer, send_packet_size, 0, (struct sockaddr *)&dest_addr, (socklen_t)sizeof(struct sockaddr)) < 0) {
			write_log(LOG_EMERG, "sendto() failed to send packet: %s", strerror(errno));
			exit(EXIT_FAILURE);
		}

		gettimeofday(&prev_time, NULL);

		/* Receive loop */
		while(1) {
			if(sig_code == SIGTERM) {
				write_log(LOG_INFO, "Signal SIGTERM received. Exiting from main loop");
				goto after_loop;
			}

			poll_res = poll(&poll_fd, 1, 100);

			if(poll_res > 0) {
				recv_packet_size = recvfrom(recvfd, recv_buffer, IP_MAXPACKET, 0, NULL, NULL);

				/* Check if destination is our host or multicast MAC address and drop packet if not */
				if(check_mac(recv_buffer, our_mac)) {
					parse_received_packet(recv_buffer, recv_packet_size);
				}
			} else if(poll_res == -1) {
				write_log(LOG_EMERG, "Error occurred while polling socket! %s", strerror(errno));
			}

			/* Check query time timeout */
			gettimeofday(&current_time, NULL);
			timersub(&current_time, &prev_time, &delta_time);
			if(timercmp(&delta_time, &query_time, >)) {
				break;
			}
		}
	}
	after_loop:
	close(sendfd);
	close(recvfd);
	return;
}

pid_t daemonize(void) {
	char pid_str[16];
	pid_t pid;

	pid = fork();

	switch(pid) {
	case 0:
		/* Try to open PID file and lock it */
		if(main_cfg.pid_file_path != NULL) {

			pid_fd = open(main_cfg.pid_file_path, O_RDWR | O_CREAT, 0640);

			if(pid_fd < 0) {
				write_log(LOG_EMERG, "Can't open PID file %s! %s", main_cfg.pid_file_path, strerror(errno));
				main_cfg.pid_file_path = NULL; /* To prevent deleting file in cleanup_and_exit() */
				break;
			}

			if(lockf(pid_fd, F_TLOCK, 0) < 0) {
				write_log(LOG_EMERG, "Can't lock PID file %s! %s", main_cfg.pid_file_path, strerror(errno));
				main_cfg.pid_file_path = NULL; /* To prevent deleting file in cleanup_and_exit() */
				break;
			}

			snprintf(pid_str, 16, "%d\n", getpid());
			write(pid_fd, pid_str, strlen(pid_str));
		}

		if(setsid() == -1) {
			write_log(LOG_EMERG, "Error occurred while running setsid()! %s", strerror(errno));
			break;
		}
		if(chdir("/") == -1) {
			write_log(LOG_EMERG, "Error occurred while running chdir()! %s", strerror(errno));
			break;
		}

		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);

		write_log(LOG_INFO, "%s get daemonized", PROG_NAME);

		return pid;
		break;
	case -1:
		printf("Error occurred while forking! %s\n", strerror(errno));
		break;
	default:
		return pid;
	}

	return -1;
}

void cleanup_and_exit(int status) {
	close_log();
	if(pid_fd > 0) {
		lockf(pid_fd, F_ULOCK, 0);
		close(pid_fd);

		if(main_cfg.pid_file_path != NULL) {
			unlink(main_cfg.pid_file_path);
		}
	}
	exit(status);
}

void print_usage(void) {
	fprintf(stderr, "%s. Ver. %s. Copyright (c) %s.\n", PROG_NAME, PROG_VERSION, PROG_COPYRIGHT);
	fprintf(stderr, "Usage: %s [options]\n", PROG_NAME);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "    -f             : Don't fork (run in interactive mode).\n");
	fprintf(stderr, "    -h             : Print help message.\n");
	fprintf(stderr, "    -i interface   : Specify network interface. Default: %s\n", DEFAULT_IF_NAME);
	fprintf(stderr, "    -l path        : Set log file path. Default: %s\n", LOG_FILE_PATH);
	fprintf(stderr, "    -L level       : Log level from 0 to 7. Default: %d\n", DEFAULT_LOG_LEVEL);
	fprintf(stderr, "    -p path        : Set PID file path. Default: %s\n", PID_FILE_PATH);
	fprintf(stderr, "    -q interval    : Set general query interval in seconds. Default: %d\n", DEFAULT_QUERY_INTERVAL);
	fprintf(stderr, "    -r interval    : Set query response interval in 1/10th of second. Default: %d\n", DEFAULT_RESP_INTERVAL);
}

int main(int argc, char **argv) {
	int opt;
	pid_t pid;

	/* Set default values of global variables */
	main_cfg.igmp_version = DEFAULT_IGMP_VER;
	main_cfg.log_file_path = LOG_FILE_PATH;
	main_cfg.pid_file_path = PID_FILE_PATH;
	main_cfg.if_name = DEFAULT_IF_NAME;
	main_cfg.query_interval = DEFAULT_QUERY_INTERVAL;
	main_cfg.resp_interval = DEFAULT_RESP_INTERVAL;
	main_cfg.flags = 0;
	main_cfg.loglevel = DEFAULT_LOG_LEVEL;

	/* Parse program arguments */
	while((opt=getopt(argc, argv, "fhi:l:L:p:q:r:")) != -1) {
			switch(opt) {
			case 'f':
				main_cfg.flags |= FLAG_INTERACTIVE;
				break;
			case 'h':
				print_usage();
				exit(EXIT_SUCCESS);
				break;
			case 'i':
				if(optarg != 0) {
					main_cfg.if_name = strdup(optarg);
				}
				break;
			case 'l':
				if(optarg != 0) {
					main_cfg.log_file_path = strdup(optarg);
				}
				main_cfg.flags &= ~FLAG_INTERACTIVE;
				break;
			case 'L':
				main_cfg.loglevel = atoi(optarg);
				break;
			case 'p':
				if(optarg != 0) {
					main_cfg.pid_file_path = strdup(optarg);
				}
				break;
			case 'q':
				main_cfg.query_interval = atoi(optarg);
				break;
			case 'r':
				main_cfg.resp_interval = atoi(optarg);
				break;
			default:
				print_usage();
				exit(EXIT_FAILURE);
			}
		}

	/* Response interval must be less than query interval */
	if(main_cfg.resp_interval >= main_cfg.query_interval*10) {
		write_log(LOG_EMERG, "Response interval must be less than query interval! Exit");
		cleanup_and_exit(EXIT_FAILURE);
	}

	/* Set log destination */
	if(main_cfg.flags & FLAG_INTERACTIVE) {
		init_log(main_cfg.loglevel, NULL);
	}
	else {
		init_log(main_cfg.loglevel, main_cfg.log_file_path);
	}

	write_log(LOG_NOTICE, "%s started", PROG_NAME);

	/* If not interactive mode then run as daemon */
	if(!(main_cfg.flags & FLAG_INTERACTIVE)) {
		pid = daemonize();
	}
	else {
		pid = 0;
	}

	if(pid == -1) {
		write_log(LOG_EMERG, "Can't daemonize %s! Exit", PROG_NAME);
		cleanup_and_exit(EXIT_FAILURE);
	}

	if(pid > 0) {
		write_log(LOG_NOTICE, "Parent exited, daemon staying run with PID %d", pid);
		cleanup_and_exit(EXIT_SUCCESS);
	}

	write_log(LOG_NOTICE, "%s successfully started", PROG_NAME);

	querier_loop();

	write_log(LOG_NOTICE, "%s finished", PROG_NAME);

	cleanup_and_exit(EXIT_SUCCESS);

	return 0;
}
