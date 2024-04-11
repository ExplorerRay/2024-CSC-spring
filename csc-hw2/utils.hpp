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

int int_ip4(struct sockaddr *addr, uint32_t *ip);
int format_ip4(struct sockaddr *addr, char *out);
int get_if_ip4(int fd, const char *ifname, uint32_t *ip);
int send_arp(int fd, int ifindex, const unsigned char *src_mac, uint32_t src_ip, uint32_t dst_ip);
int send_arp_rply();
int get_if_info(const char *ifname, uint32_t *ip, unsigned char *mac, int *ifindex);
int bind_arp(int ifindex, int *fd);
int read_arp(int fd, std::map<std::string, std::string> &arp_table);
int test_arp(const char *ifname, uint32_t ip, std::map<std::string, std::string> &arp_table);
//int test_arp(uint32_t src, uint32_t ip, int arp_fd, int ifindex, unsigned char *mac);
