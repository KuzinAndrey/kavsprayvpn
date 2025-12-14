/*
///////////////////////////////////////////////////////

kavsprayvpn - spray packet for VPN connection to prevent traffic analysis by DPI

Author: kuzinandrey@yandex.ru

URL: https://www.github.com/KuzinAndrey/kavsprayvpn

///////////////////////////////////////////////////////
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>

#include <net/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>

#ifndef PRODUCTION
#include <sys/resource.h>
#define TRACE fprintf(stderr,"TRACE %s:%d - %s()\n", __FILE__, __LINE__, __func__);
#define DEBUG(...) fprintf(stderr, __VA_ARGS__);
#else
#define TRACE
#define DEBUG(...)
#endif

#include "dynamic_array.h"

int program_state = 0; // 2 - exit
int run_command(const char *fmt, ...);

///////////////////////////////////////////////////////
//////// TUN
///////////////////////////////////////////////////////

struct tun_connection {
	int tun_fd;
	char tun_name[IFNAMSIZ];
};

// OPEN TUN DEVICE (return -1 if error)
bool up_tun_iface(struct tun_connection *conn, const char *name) {
	struct ifreq ifr;
	int retry = 0;

	if (!conn || !name) return false;

retry:
	if ((conn->tun_fd = open("/dev/net/tun", O_RDWR)) < 0) {
		fprintf(stderr,"Can't open /dev/net/tun: %s\n", strerror(errno));
		if (errno == ENOENT) {
			if (0 == run_command("modprobe tun") && !retry) {
				retry++;
				goto retry;
			}
		}
		return false;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	strncpy(ifr.ifr_name, name, IFNAMSIZ);

	if (ioctl(conn->tun_fd, TUNSETIFF, (void *) &ifr) < 0) {
		fprintf(stderr,"Can't ioctl: %s\n", strerror(errno));
		return false;
	}

	strcpy(conn->tun_name, ifr.ifr_name);
	DEBUG("Open tun device: %s\n",conn->tun_name);

	return true;
} // up_tun_iface()

// CLOSE TUN DEVICE
int down_tun_iface(struct tun_connection *conn) {
	int ret = -1;
	if (conn && conn->tun_fd > 2) {
		ret = close(conn->tun_fd);
		if (ret == 0) conn->tun_fd = 0;
	}
	return ret;
} // down_tun_iface()

///////////////////////////////////////////////////////
//////// SESSIONS
///////////////////////////////////////////////////////
struct spray_session {
	struct in_addr remote_ip;
	char secret[128];
	char session[1024];
	time_t session_init;
	enum {
		STATE_UNKNOWN = 0,
		STATE_INIT,
		STATE_WORK,
	} state;
};


const char *iptables_bin = NULL;
const char *iptables_search[] = {
	"/usr/local/sbin/iptables",
	"/usr/local/bin/iptables",
	"/usr/sbin/iptables",
	"/usr/bin/iptables",
	"/sbin/iptables",
	"/usr/iptables",
	NULL };

const char *ip_bin = NULL;
const char *ip_search[] = {
	"/usr/local/sbin/ip",
	"/usr/local/bin/ip",
	"/usr/sbin/ip",
	"/usr/bin/ip",
	"/sbin/ip",
	"/usr/ip",
	NULL };

DYNAMIC_ARRAY_DECLARE(struct spray_session, sess);

///////////////////////////////////////////////////////
//////// FUNCTIONS
///////////////////////////////////////////////////////

bool find_commands() {
	for (const char **t = iptables_search; *t; t++) {
		if (0 == access(*t, R_OK | X_OK)) { iptables_bin = *t; break; }
	}
	if (!iptables_bin) {
		fprintf(stderr,"Can't found 'iptables' executable !\n");
		return false;
	}

	for (const char **t = ip_search; *t; t++) {
		if (0 == access(*t, R_OK | X_OK)) { ip_bin = *t; break; }
	}
	if (!ip_bin) {
		fprintf(stderr,"Can't found 'ip' executable !\n");
		return false;
	}

	return true;
}

int run_command(const char *fmt, ...) {
	char *com = NULL;
	int comret = 0;
	int ret = -1; // default error

	va_list arg_list;
	va_start(arg_list, fmt);
	ret = vasprintf(&com, fmt, arg_list);
	va_end(arg_list);
	if (ret == -1) goto defer;

	printf("+ %s",com);
	comret = system(com);
	printf(" = %d\n", comret);
	if (comret == -1) {
		fprintf(stderr, "Can't run command: \"%s\" - %s\n", com, strerror(errno));
	} else if (comret != 0) {
		fprintf(stderr, "Command \"%s\" return not zero code %d\n", com, comret);
	} else ret = comret;
defer:
	if (com) free(com);
	return ret;
} // run_command()


///////////////////////////////////////////////////////
//////// MAIN
///////////////////////////////////////////////////////
int main(int argc, char **argv) {
	int ret = 0;
	char tun_buffer[0xFFFF] = {0};
	struct tun_connection conn = {0};
	int tun_number = 1;
	char opt_tun_iface[IFNAMSIZ];
	struct in_addr tun_ptp_subnet;
	struct in_addr local_ptp_ip;
	struct in_addr remote_ptp_ip;
	char *optarg;

	enum work_mode_en {
		WORK_MODE_UNKNOWN = 0,
		WORK_MODE_SERVER,
		WORK_MODE_CLIENT,
	} work_mode = WORK_MODE_UNKNOWN;

	DYNAMIC_ARRAY_INIT(sess);

	if (0 != geteuid()) {
		fprintf(stderr,"You can't run program under unprivileged user!\n"
			"Use: sudo %s\n", argv[0]);
		return 1;
	}

	if (!find_commands()) return 1;

/////////////////////////
// TODO parse options
	optarg = "10.66.77.0";

	if (!inet_pton(AF_INET, optarg, &tun_ptp_subnet)) {
		fprintf(stderr,"Can't parse \"%s\" as point-to-point /30 subnet\n", optarg);
		return 1;
	};
	work_mode = WORK_MODE_CLIENT;
/////////////////////////

	// Prepare tun variables
	// TODO use opt_tun_iface if defined and check it
	while (1) { // find empty name for tun device
		sprintf(tun_buffer, "/proc/sys/net/ipv4/conf/tun%d", tun_number);
		if (access(tun_buffer, F_OK) == -1) break;
		tun_number++;
	}; // while
	sprintf(opt_tun_iface, "tun%d", tun_number);

	if (!up_tun_iface(&conn, opt_tun_iface)) {
		fprintf(stderr,"Can't create tun iface: %s\n", opt_tun_iface);
		return 1;
	}

	if (0 != run_command("%s link set %s up", ip_bin, conn.tun_name)) {
		fprintf(stderr, "Can't up tun iface\n");
		ret = 1;
		goto exit_tun;
	}

	// Set IP for local tun iface
	local_ptp_ip = tun_ptp_subnet;
	remote_ptp_ip = tun_ptp_subnet;
	if (work_mode == WORK_MODE_SERVER) {
		local_ptp_ip.s_addr += ntohl(1);
		remote_ptp_ip.s_addr += ntohl(2);
	} else {
		local_ptp_ip.s_addr += ntohl(2);
		remote_ptp_ip.s_addr += ntohl(1);
	};

	if (0 != run_command("%s address add %s/24 dev %s", ip_bin,
		inet_ntoa(local_ptp_ip), conn.tun_name)
	) {
		fprintf(stderr, "error set ip address on tun iface\n");
		goto exit_tun_link;
	};

	// Main work cycle
	while (0 != access("./.break", F_OK)) {
		printf("working\n");
		sleep(10);
	}
	unlink("./.break");

//exit_tun_ip:
	run_command("%s address del %s/24 dev %s", ip_bin,
		inet_ntoa(local_ptp_ip), conn.tun_name);

exit_tun_link:
	run_command("%s link set %s down", ip_bin, conn.tun_name);

exit_tun:
	down_tun_iface(&conn);
	DYNAMIC_ARRAY_FREE(sess);
	return ret;
}
