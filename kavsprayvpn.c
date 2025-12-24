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
#include <time.h>

#include <net/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>

#include <inttypes.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
// #include <netinet/ip6.h>
#include <netinet/udp.h>
#include <linux/netfilter.h>
#include <libnfnetlink/libnfnetlink.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <openssl/evp.h>

#ifndef PRODUCTION
#include <sys/resource.h>
#define TRACE fprintf(stderr,"TRACE %s:%d - %s()\n", __FILE__, __LINE__, __func__);
#define DEBUG(...) fprintf(stderr, __VA_ARGS__);
#else
#define TRACE
#define DEBUG(...)
#endif

#include "dynamic_array.h"
#include "crypto.h"

int program_state = 0; // 2 - exit
int run_command(const char *fmt, ...);


// Spray port diapazon
uint16_t opt_start_port = 1025;
uint16_t opt_end_port = 65535;
uint16_t diapazon = 64510; // end - start
size_t opt_change_port = 1000;
int opt_subnet_prefix = 24;

static char recv_buffer[0xFFFF] = {0};
static char crypto_buffer[0xFFFF + 128] = {0};
static EVP_CIPHER_CTX *ctx = NULL;

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

static struct tun_connection conn = {0};
static int tun_number = 1;
static char opt_tun_iface[IFNAMSIZ];
static struct in_addr tun_ptp_subnet;
static struct in_addr local_ptp_ip;
static struct in_addr remote_ptp_ip;
static int opt_tun_ptp_subnet = 0;

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
//////// ENCRYPTION
///////////////////////////////////////////////////////
// Get portion of key data from built-in crypto array (see crypto.h)
void get_crypto_array_part(size_t pos, void *buf, size_t buf_size) {
	memcpy(buf, (char *)crypto_h_array + pos %
		(CRYPTO_H_ARRAY_SIZE - buf_size + 1), buf_size);
}


// Encrypt data buffer by random key & iv from global crypto array
int encrypt_data(EVP_CIPHER_CTX *ctx, const char *data, size_t data_len,
	char *outdata, size_t *outdata_len)
{
	int key_pos = rand();
	int iv_pos = rand();
	unsigned char key[32];
	unsigned char iv[16];
	unsigned char *p = (unsigned char*)outdata;
	size_t s = 0;
	int len;

	if (!ctx || !data || !outdata || !outdata_len) return -1;
	*outdata_len = 0;

	get_crypto_array_part(key_pos, key, sizeof(key));
	get_crypto_array_part(iv_pos, iv, sizeof(iv));

	memcpy(p, &key_pos, sizeof(key_pos));
	s += sizeof(key_pos);

	memcpy(p + s, &iv_pos, sizeof(iv_pos));
	s += sizeof(iv_pos);

	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) goto error;

	if (1 != EVP_EncryptUpdate(ctx, p + s, &len, (unsigned char *)data, data_len)) goto error;
	s += len;

	if (1 != EVP_EncryptFinal_ex(ctx, p + s, &len)) goto error;
	s += len;

	*outdata_len = s;
	return 0;

error:
	*outdata_len = 0;
	return -1;
}

// Decrypt data buffer by key & iv position from global crypto array
int decrypt_data(EVP_CIPHER_CTX *ctx, const char *data, size_t data_len,
	char *outdata, size_t *outdata_len)
{
	int key_pos = rand();
	int iv_pos = rand();
	unsigned char key[32];
	unsigned char iv[16];
	unsigned char *p = (unsigned char*)outdata;
	size_t s = 0;
	int len;

	if (!ctx || !data || !outdata || !outdata_len) return -1;
	*outdata_len = 0;

	memcpy(&key_pos, data, sizeof(key_pos));
	s += sizeof(key_pos);

	memcpy(&iv_pos, data + s, sizeof(iv_pos));
	s += sizeof(iv_pos);

	get_crypto_array_part(key_pos, key, sizeof(key));
	get_crypto_array_part(iv_pos, iv, sizeof(iv));

	if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) goto error;

	if (1 != EVP_DecryptUpdate(ctx, p, &len, (unsigned char *)data + s, data_len - s)) goto error;
	s = len;

	if (1 != EVP_DecryptFinal_ex(ctx, p + s, &len)) goto error;
	s += len;

	*outdata_len = s;
	return 0;

error:
	*outdata_len = 0;
	return -1;
}

///////////////////////////////////////////////////////
//////// NETFILTER
///////////////////////////////////////////////////////

// Callback function for NFQUEUE handler
static int vpn_nfq_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	struct nfq_data *nfa, void *data) {

	int ret;
	uint32_t id;
	struct nfqnl_msg_packet_hdr *ph;
	unsigned char *payload;
	size_t payload_len;
#ifndef PRODUCTION
	struct timeval nfq_tv;
	char ipaddr[128];
#endif

	struct ip *ip_packet;
	uint16_t ip_packet_len;
	struct in_addr in = {0};

	struct udphdr *udp_packet = NULL;
	uint16_t udp_port = 0;
	uint16_t udp_packet_len = 0;
	int found_sess = -1;

	ph = nfq_get_msg_packet_hdr(nfa);
	id = ntohl(ph->packet_id);

#ifndef PRODUCTION
	if (0 != nfq_get_timestamp(nfa, &nfq_tv)) {
		nfq_tv.tv_sec = time(NULL);
		nfq_tv.tv_usec = 0;
	}
#endif

	ret = nfq_get_payload(nfa, &payload);
	if (ret <= 0 || !payload) goto verdict;
	payload_len = ret;

	if (payload_len < sizeof(struct ip)) goto verdict;

	ip_packet = (struct ip *)payload;


	// Detect IP protocol version
	if (4 == ip_packet->ip_v) {
		// IPv4
		size_t ip_hl;
		in = ip_packet->ip_src;
		ip_hl = ip_packet->ip_hl * 4;
		ip_packet_len = ntohs(ip_packet->ip_len);
		if (IPPROTO_UDP == ip_packet->ip_p
			&& ip_packet_len >= ip_hl + sizeof(struct udphdr)
		) {
			udp_packet = (struct udphdr *)(payload + ip_hl);
			udp_port = ntohs(udp_packet->uh_dport);
			udp_packet_len = ntohs(udp_packet->uh_ulen);
		}

#ifndef PRODUCTION
		inet_ntop(AF_INET, &in, ipaddr, sizeof(ipaddr));
#endif
//	} else if (6 == ip_packet->ip_v) {
//		// TODO IPv6
	}

	if (!udp_packet) goto verdict;

	if (udp_port < opt_start_port || udp_port > opt_end_port) goto verdict;

	DYNAMIC_ARRAY_FOREACH(sess, i, {
		if (sess.data[i].remote_ip.s_addr == in.s_addr) {
			DEBUG("%ld: found session %d\n", nfq_tv.tv_sec, found_sess);
			found_sess = i;
			break;
		}
	});

	if (found_sess < 0) {
		goto verdict;
	}

	DEBUG("%ld: get UDP packet on port %" PRIu16 " from %s (UDP length %d) IP len %d\n",
		nfq_tv.tv_sec, udp_port, ipaddr, udp_packet_len, ip_packet_len);

	if (decrypt_data(ctx, (char *)(udp_packet) + sizeof(struct udphdr),
		udp_packet_len - sizeof(struct udphdr),
		crypto_buffer, &payload_len) < 0) goto verdict;

	write(conn.tun_fd, crypto_buffer, payload_len);

	return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);

verdict:
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

// Function for tun packet work
static ssize_t tun_handle_packet(int sock_fd, char *buf, size_t buf_len) {
	struct ip *ip_packet;
//	uint16_t ip_packet_len;
	struct sockaddr_in dest = {0};
	ssize_t n = 0;
	size_t payload_len = 0;
	int session = -1;
#ifndef PRODUCTION
	char ipaddr1[128];
	char ipaddr2[128];
#endif

//	struct udphdr *udp_packet = NULL;
//	uint16_t udp_port;

	// TODO find session by remote ip
	if (sess.count > 0) session = 0;

	if (session < 0) return 0;
	ip_packet = (struct ip *)buf;

	if (4 == ip_packet->ip_v) {
//		ip_packet_len = ntohs(ip_packet->ip_len);
#ifndef PRODUCTION
		if (inet_ntop(AF_INET, &ip_packet->ip_src, ipaddr1, sizeof(ipaddr1))
		    && inet_ntop(AF_INET, &ip_packet->ip_dst, ipaddr2, sizeof(ipaddr2))
		) {
			DEBUG("recv packet %s -> %s, len %d\n", ipaddr1, ipaddr2, ntohs(ip_packet->ip_len));
		}
#endif
		dest.sin_family = AF_INET;
		dest.sin_port = htons(opt_start_port + rand() % diapazon);
		dest.sin_addr = sess.data[session].remote_ip;

		if (encrypt_data(ctx, buf, buf_len, crypto_buffer, &payload_len) < 0) {
			n = -1;
			goto exit;
		}

		n = sendto(sock_fd, crypto_buffer, payload_len, 0, (struct sockaddr *)&dest, sizeof(dest));
		if (n < 0) {
			DEBUG("Failed sendto");
		}
	}
exit:
	return n;
}

void signal_handler(int sig) {
	switch (sig) {
		case SIGINT:
		case SIGTERM:
			program_state = 2; //exit main cycle
		break;
	} // swtich
} // signal_handler()


#define UDP_OUTPORT_SIZE 128

void print_help(const char *prog) {
	printf("Spray VPN daemon (home: https://github.com/KuzinAndrey/kavsprayvnp)\n");
	printf("\n");
	printf("Usage: %s [options]\n", prog);
	printf("Options:\n");
	printf("\t-h - this help\n");
	printf("\t-s - work as server side (run iptables with NAT & FORWARD rules)\n");
	printf("\t-c - work as client size\n");
	printf("\t-a [port] - start UDP port diapazon\n");
	printf("\t-b [port] - end UDP port diapazon\n");
	printf("\t-n [subnet] - P-t-P subnet to set IP on tun iface (can be prefixed by /NN)\n");
	printf("\t     Example: 10.66.77.0 (or 10.66.77.0/30 or 10.66.77.0/24)\n");
	printf("\t       server side automatically get 10.66.77.1\n");
	printf("\t       client side automatically get 10.66.77.2\n");
	printf("\t-r [ip] - remote IP address\n");
	printf("Example:\n");
	printf("\tConnection between 111.222.10.20(server) <-> 190.190.30.10(client)\n");
	printf("\tOn 111.222.10.20:\n");
	printf("\t\t%s -s -n 10.10.10.0/30 -a 43123 -b 55412 -r 190.190.30.10\n", prog);
	printf("\tOn 190.190.30.10:\n");
	printf("\t\t%s -c -n 10.10.10.0/30 -a 43123 -b 55412 -r 111.222.10.20\n", prog);
	exit(EXIT_SUCCESS);
}

///////////////////////////////////////////////////////
//////// MAIN
///////////////////////////////////////////////////////
int main(int argc, char **argv) {
	int ret = 0;
	int opt = 0;

	// NFQUEUE variables
	uint16_t opt_queue_id = 69;
	uint32_t opt_queue_maxlen = 10000;
	int opt_touch_iptables = 1;
	int iptables_nfqueue_rule = 0;
	int iptables_nat_rule = 0;
	int iptables_forward1_rule = 0;
	int iptables_forward2_rule = 0;

	// Netfilter
	struct nfq_handle *netfilter_h = NULL;
	struct nfnl_handle *netfilter_nh = NULL;
	struct nfq_q_handle *netfilter_qh = NULL;
	int netfilter_fd;

	fd_set rfds;
	struct timeval rfds_tv;

	int udp_fd[UDP_OUTPORT_SIZE];
	size_t udp_count[UDP_OUTPORT_SIZE];

	enum work_mode_en {
		WORK_MODE_UNKNOWN = 0,
		WORK_MODE_SERVER,
		WORK_MODE_CLIENT,
	} work_mode = WORK_MODE_UNKNOWN;

	DYNAMIC_ARRAY_INIT(sess);


	while ((opt = getopt(argc, argv, "hsca:b:n:r:")) != -1)
	switch (opt) {
		case 'h': print_help(argv[0]); break;

		case 's': case 'c':
			if (work_mode == WORK_MODE_UNKNOWN) {
				work_mode = (opt == 'c' ? WORK_MODE_CLIENT : WORK_MODE_SERVER);
			} else {
				fprintf(stderr, "ERROR: You can't mixing server and client mode\n");
				return 1;
			}
		break;

		case 'a': case 'b': {
			char *e;
			int val = strtod(optarg, &e);
			if (*e != '\0') {
				fprintf(stderr, "ERROR: Can't parse port number %s\n", optarg);
				return 1;
			}
			if (val < 1025 || val > 65535) {
				fprintf(stderr, "ERROR: Wrong port number %d, must be in 1025-65535\n", val);
				return 1;
			}
			if (opt == 'a') opt_start_port = val; else opt_end_port = val;
		} break;

		case 'n': { // tun subnet address
			char ipnet[128];
			char *s, *e;
			if (snprintf(ipnet, sizeof(ipnet), "%s", optarg) >= sizeof(ipnet)) {
				fprintf(stderr, "ERROR: Can't parse too long value of \"-n %s\"\n", optarg);
				return 1;
			}
			s = strchr(ipnet, '/');
			if (s) {
				*s++ = '\0';
				opt_subnet_prefix = strtod(s, &e);
				if (*e != '\0') {
					fprintf(stderr, "ERROR: Can't parse subnet prefix \"%s\" in %s\n", s, optarg);
					return 1;
				}
				if (opt_subnet_prefix < 0 || opt_subnet_prefix > 30) {
					fprintf(stderr, "ERROR: Wrong subnet prefix %d, can be 0..30\n", opt_subnet_prefix);
					return 1;
				}
			}
			if (!inet_pton(AF_INET, ipnet, &tun_ptp_subnet)) {
				fprintf(stderr, "ERROR: Can't parse \"%s\" as point-to-point subnet\n", optarg);
				return 1;
			}
			if ((ntohl(tun_ptp_subnet.s_addr) & (0xFFFFFFFF << (32 - opt_subnet_prefix))) != ntohl(tun_ptp_subnet.s_addr)) {
				fprintf(stderr, "ERROR: Wrong network address %s for prefix /%d\n", inet_ntoa(tun_ptp_subnet), opt_subnet_prefix);
				return 1;
			}
			opt_tun_ptp_subnet = 1;
		} break;

		case 'r': { // remote point IP
			struct spray_session new = {0};
			if (!inet_pton(AF_INET, optarg, &new.remote_ip)) {
				fprintf(stderr, "ERROR: Can't parse \"%s\" as remote IP\n", optarg);
				return 1;
			}
			DYNAMIC_ARRAY_PUSH(sess, new);
		} break;
	} // switch opt

	if (0 != geteuid()) {
		fprintf(stderr, "ERROR: You can't run program under unprivileged user!\n");
		fprintf(stderr, "Use: sudo %s\n", argv[0]);
		return 1;
	}

	if (!find_commands()) return 1;

	if (!opt_tun_ptp_subnet) {
		fprintf(stderr, "ERROR: unknown tun subnet (use -n)\n");
		return 1;
	}

	if (opt_start_port == opt_end_port) {
		fprintf(stderr, "ERROR: Start and End port are equal -a %d == -b %d\n", opt_start_port, opt_end_port);
		return 1;
	}

	if (sess.count == 0) {
		fprintf(stderr, "ERROR: No any remote IP address (use -r)\n");
		return 1;
	}

	if (work_mode == WORK_MODE_UNKNOWN) {
		fprintf(stderr, "ERROR: Unknown working mode, use -s for server or -c for client mode\n");
		return 1;
	}

	if (opt_end_port < opt_start_port) {
		opt_end_port ^= opt_start_port;
		opt_start_port ^= opt_end_port;
		opt_end_port ^= opt_start_port;
	}
	diapazon = opt_end_port - opt_start_port;

	if (!(ctx = EVP_CIPHER_CTX_new())) return 1;

	for (size_t i = 0; i < UDP_OUTPORT_SIZE; i++) {
		if ((udp_fd[i] = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
			fprintf(stderr, "UDP socket creation error\n");
			return 1;
		}
		udp_count[i] = 0;
	}

	// Prepare tun variables
	// TODO use opt_tun_iface if defined and check it
	while (1) { // find empty name for tun device
		sprintf(recv_buffer, "/proc/sys/net/ipv4/conf/tun%d", tun_number);
		if (access(recv_buffer, F_OK) == -1) break;
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

	if (0 != run_command("%s address add %s/%d dev %s", ip_bin,
		inet_ntoa(local_ptp_ip), opt_subnet_prefix, conn.tun_name)
	) {
		fprintf(stderr, "error set ip address on tun iface\n");
		ret = 1;
		goto exit_tun_link;
	};

#define IPTABLES_NFQUEUE_TEMPLATE \
	"%s -%s INPUT -p udp --dport %d:%d " \
	"-j NFQUEUE --queue-bypass --queue-num %d 2> /dev/null"

#define IPTABLES_NAT_TEMPLATE \
	"%s -t nat -%s POSTROUTING ! -o %s -j MASQUERADE 2> /dev/null"

#define IPTABLES_FORWARD1_TEMPLATE \
	"%s -%s FORWARD ! -o %s -i %s -j ACCEPT 2> /dev/null"

#define IPTABLES_FORWARD2_TEMPLATE \
	"%s -%s FORWARD ! -i %s -o %s -j ACCEPT 2> /dev/null"

	// Add iptables rule if it not present
	if (opt_touch_iptables && iptables_bin) {
		if (0 != run_command(IPTABLES_NFQUEUE_TEMPLATE, iptables_bin, "C",
				     opt_start_port, opt_end_port, opt_queue_id)
		) {
			if (0 != run_command(IPTABLES_NFQUEUE_TEMPLATE, iptables_bin, "I",
					     opt_start_port, opt_end_port, opt_queue_id)
			) {
				fprintf(stderr, "Error: Cannot create iptables rule\n");
				ret = 1;
				goto exit_tun_ip;
			} else iptables_nfqueue_rule = 1;
		}

		if (work_mode == WORK_MODE_SERVER) {
			if (0 != run_command(IPTABLES_NAT_TEMPLATE, iptables_bin, "C", conn.tun_name)
			) {
				if (0 != run_command(IPTABLES_NAT_TEMPLATE, iptables_bin, "I", conn.tun_name)
				) {
					fprintf(stderr, "Error: Cannot create iptables rule\n");
					ret = 1;
					goto exit_iptables;
				} else iptables_nat_rule = 1;
			}

			if (0 != run_command(IPTABLES_FORWARD1_TEMPLATE, iptables_bin, "C",
					     conn.tun_name, conn.tun_name)
			) {
				if (0 != run_command(IPTABLES_FORWARD1_TEMPLATE, iptables_bin, "I",
						     conn.tun_name, conn.tun_name)
				) {
					fprintf(stderr, "Error: Cannot create iptables rule\n");
					ret = 1;
					goto exit_iptables;
				} else iptables_forward1_rule = 1;
			}

			if (0 != run_command(IPTABLES_FORWARD2_TEMPLATE, iptables_bin, "C",
					     conn.tun_name, conn.tun_name)
			) {
				if (0 != run_command(IPTABLES_FORWARD2_TEMPLATE, iptables_bin, "I",
						     conn.tun_name, conn.tun_name)
				) {
					fprintf(stderr, "Error: Cannot create iptables rule\n");
					ret = 1;
					goto exit_iptables;
				} else iptables_forward2_rule = 1;
			}
		} // MODE_SERVER
	}

#ifdef PRODUCTION
	if (daemon(0, 0) != 0) {
		fprintf(stderr,"Can't daemonize process!\n");
		goto exit;
	};
#endif

	// Prepare Netfilter Queue library
	netfilter_h = nfq_open();
	if (!netfilter_h) {
		fprintf(stderr, "Error: Cannot open NFQUEUE handle\n");
		ret = 1; goto exit;
	}

	netfilter_nh = nfq_nfnlh(netfilter_h);
	netfilter_fd = nfnl_fd(netfilter_nh);

	netfilter_qh = nfq_create_queue(netfilter_h, opt_queue_id, &vpn_nfq_callback, NULL);
	if (!netfilter_qh) {
		fprintf(stderr, "Error: Cannot create NFQUEUE %" PRIu16 "\n", opt_queue_id);
		ret = 1; goto exit;
	}

	if (nfq_set_queue_maxlen(netfilter_qh, opt_queue_maxlen) < 0) {
		fprintf(stderr, "Warning: Cannot set queue maxlen to %" PRIu32 "\n", opt_queue_maxlen);
	}

	// Accept all packets if queue is full (not drop it)
	if (nfq_set_queue_flags(netfilter_qh, NFQA_CFG_F_FAIL_OPEN, NFQA_CFG_F_FAIL_OPEN) < 0) {
		fprintf(stderr, "Warning: Cannot set fail-open flag\n");
	}

	// Copy full packet
	if (nfq_set_mode(netfilter_qh, NFQNL_COPY_PACKET, sizeof(recv_buffer)) < 0) {
		fprintf(stderr, "Error: Cannot set packet copy mode\n");
		ret = 1; goto exit;
	}

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	// Main work cycle
	while (2 != program_state) {
		// Get NFQUEUE packet for work
		int max_fd = 0;
		ssize_t recv_len;
		rfds_tv.tv_sec = 1; rfds_tv.tv_usec = 0;
		FD_ZERO(&rfds);
		FD_SET(netfilter_fd,&rfds);
		FD_SET(conn.tun_fd,&rfds);
		max_fd = (netfilter_fd > conn.tun_fd ? netfilter_fd : conn.tun_fd);
		if (select(max_fd + 1, &rfds, NULL, NULL, &rfds_tv) > 0) {
			if (FD_ISSET(netfilter_fd, &rfds)) {
				recv_len = recv(netfilter_fd, recv_buffer, sizeof(recv_buffer), 0);
				if (recv_len >= 0) {
					nfq_handle_packet(netfilter_h, recv_buffer, recv_len);
				}
			}
			if (FD_ISSET(conn.tun_fd, &rfds)) {
				recv_len = read(conn.tun_fd, recv_buffer, sizeof(recv_buffer));
				if (recv_len >= 0) {
					size_t rand_port = rand() % UDP_OUTPORT_SIZE;
					tun_handle_packet(udp_fd[rand_port], recv_buffer, recv_len);
					udp_count[rand_port]++;

					// Change outgoing UDP port every opt_change_port packets
					if (udp_count[rand_port] > opt_change_port) {
						close(udp_fd[rand_port]);
						if ((udp_fd[rand_port] = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
							goto exit;
						} else udp_count[rand_port] = 0;
					}
				}
			}
		}
	}

exit:
	if (netfilter_qh) nfq_destroy_queue(netfilter_qh);
	if (netfilter_h) nfq_close(netfilter_h);

exit_iptables:
	if (iptables_forward2_rule && iptables_bin) {
		if (0 != run_command(IPTABLES_FORWARD2_TEMPLATE, iptables_bin, "D",
				     conn.tun_name, conn.tun_name)
		) {
			fprintf(stderr, "Error: Cannot delete iptables rule\n");
		}
	}

	if (iptables_forward1_rule && iptables_bin) {
		if (0 != run_command(IPTABLES_FORWARD1_TEMPLATE, iptables_bin, "D",
				     conn.tun_name, conn.tun_name)
		) {
			fprintf(stderr, "Error: Cannot delete iptables rule\n");
		}
	}

	if (iptables_nat_rule && iptables_bin) {
		if (0 != run_command(IPTABLES_NAT_TEMPLATE, iptables_bin, "D", conn.tun_name)
		) {
			fprintf(stderr, "Error: Cannot delete iptables rule\n");
		}
	}

	if (iptables_nfqueue_rule && iptables_bin) {
		if (0 != run_command(IPTABLES_NFQUEUE_TEMPLATE, iptables_bin, "D",
				     opt_start_port, opt_end_port, opt_queue_id)
		) {
			fprintf(stderr, "Error: Cannot delete iptables rule\n");
		}
	}

exit_tun_ip:
	run_command("%s address del %s/24 dev %s", ip_bin,
		inet_ntoa(local_ptp_ip), conn.tun_name);

exit_tun_link:
	run_command("%s link set %s down", ip_bin, conn.tun_name);

exit_tun:
	for (size_t i = 0; i < UDP_OUTPORT_SIZE; i++) {
		if (udp_fd[i] > 0) close(udp_fd[i]);
	}
	down_tun_iface(&conn);
	if (ctx) EVP_CIPHER_CTX_free(ctx);
	DYNAMIC_ARRAY_FREE(sess);
	return ret;
}
