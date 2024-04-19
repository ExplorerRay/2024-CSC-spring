#include <iostream>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset()
#include <netinet/ip.h>       // IP_MAXPACKET (65535)
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t
#include <sys/socket.h>       // needed for socket()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <linux/if_ether.h>   // ETH_P_ARP = 0x0806, ETH_P_ALL = 0x0003
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <errno.h>            // errno, perror()
#include <asm/types.h>
#include <stdio.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <map>
#include <thread>
#include <vector>
#include <chrono>
#include <sstream>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#define PROTO_ARP 0x0806
#define ETH2_HEADER_LEN 14
#define HW_TYPE 1
#define MAC_LENGTH 6
#define IPV4_LENGTH 4
#define ARP_REQUEST 0x01 // Taken from <linux/if_arp.h>
#define ARP_REPLY 0x02
#define BUF_SIZE 60

#define debug(x...) printf(x);printf("\n");
#define info(x...) printf(x);printf("\n");
#define warn(x...) printf(x);printf("\n");
#define err(x...) printf(x);printf("\n");

using namespace std;

struct need_info {
  const char *ifname;
  map<string, string> arp_table;
};

// Define an struct for ARP header
struct arp_header {
  uint16_t htype; // hardware type
  uint16_t ptype; // protocol type
  uint8_t hlen; // hardware address length
  uint8_t plen; // protocol address length
  uint16_t opcode; // operation type

  // when hlen = 6(ethernet), plen = 4(ipv4)
  uint8_t sender_mac[MAC_LENGTH];
  uint8_t sender_ip[IPV4_LENGTH];
  uint8_t target_mac[MAC_LENGTH];
  uint8_t target_ip[IPV4_LENGTH];
};

struct dns_hdr {
  uint16_t id;
  uint16_t flags;
  uint16_t qs_cnt;
  uint16_t ans_cnt;
  uint16_t authrr_cnt;
  uint16_t addrr_cnt;
};
struct __attribute__((packed, aligned(2))) resp_hdr {
  uint16_t name;
  uint16_t type;
  uint16_t cls; // class
  uint32_t ttl;
  uint16_t len;
};

struct __attribute__((packed, aligned(1))) ip_hdr {
  uint8_t ihl:4, ver:4;
  uint8_t tos;
  uint16_t tlen;
  uint16_t id;
  uint16_t flags;
  uint8_t ttl;
  uint8_t proto;
  uint16_t checksum;
  uint32_t src_ip;
  uint32_t dst_ip;
};
struct udp_hdr {
  uint16_t src_port;
  uint16_t dst_port;
  uint16_t len;
  uint16_t checksum;
};

int analyze_packet (char * data, int len, int type, struct need_info info);
void send_dns_reply(char *payload, int len, int qlens, struct need_info info);
void send_data_udp(char *data, int len, struct need_info info);
//void print_packet (unsigned char *buf, uint32_t len);
pair<uint,uint> print_pkt (struct nfq_data *tb, int type, struct need_info info);
int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);
int cb_dns(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);
void nfq_thread(int type, struct need_info info);
// void filter_thread(const char *ifname);s
void str2mac(const char *txt, unsigned char *mac);
// std::vector<unsigned char> str2mac(const char *txt, std::vector<unsigned char> mac);
int int_ip4(struct sockaddr *addr, uint32_t *ip);
// int format_ip4(struct sockaddr *addr, char *out);
int get_if_ip4(int fd, const char *ifname, uint32_t *ip);
int send_arp(int fd, int ifindex, const unsigned char *src_mac, uint32_t src_ip, uint32_t dst_ip);
int arp_reply(int ifindex, unsigned char *src_mac, unsigned char *dst_mac, uint32_t src_ip, uint32_t dst_ip);
void thread_reply(const char *ifname, vector<string> vctms, map<string, string> arp_table, unsigned char *gw_mac, uint32_t gw_ip);
int get_if_info(const char *ifname, uint32_t *ip, unsigned char *mac, int *ifindex);
//int bind_all(int ifindex, int *fd);
int bind_arp(int ifindex, int *fd);
int read_arp(int fd, std::map<std::string, std::string> &arp_table);
int test_arp(const char *ifname, uint32_t ip, std::map<std::string, std::string> &arp_table);
//int test_arp(uint32_t src, uint32_t ip, int arp_fd, int ifindex, unsigned char *mac);
