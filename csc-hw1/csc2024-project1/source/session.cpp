#include "session.h"

#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <iostream>
#include <span>
#include <utility>

extern bool running;

Session::Session(const std::string& iface, ESPConfig&& cfg)
    : sock{0}, recvBuffer{}, sendBuffer{}, config{std::move(cfg)}, state{} {
  checkError(sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL)), "Create socket failed");
  // TODO: Setup sockaddr_ll
  sockaddr_ll addr_ll{};
  addr_ll.sll_family = AF_PACKET;
  addr_ll.sll_protocol = htons(ETH_P_ALL);
  addr_ll.sll_ifindex = if_nametoindex(iface.c_str());
  addrLen = sizeof(addr_ll);
  checkError(bind(sock, reinterpret_cast<sockaddr*>(&addr_ll), addrLen), "Bind failed");
}

Session::~Session() {
  shutdown(sock, SHUT_RDWR);
  close(sock);
}

void Session::run() {
  epoll_event triggeredEvent[2];
  epoll_event event;
  Epoll ep;

  event.events = EPOLLIN;
  event.data.fd = 0;
  checkError(epoll_ctl(ep.fd, EPOLL_CTL_ADD, 0, &event), "Failed to add stdin to epoll");
  event.data.fd = sock;
  checkError(epoll_ctl(ep.fd, EPOLL_CTL_ADD, sock, &event), "Failed to add sock to epoll");

  std::string secret;
  std::cout << "You can start to send the message...\n";
  while (running) {
    int cnt = epoll_wait(ep.fd, triggeredEvent, 2, 500);
    for (int i = 0; i < cnt; i++) {
      if (triggeredEvent[i].data.fd == 0) {
        std::getline(std::cin, secret);
      } else {
        ssize_t readCount = recvfrom(sock, recvBuffer, sizeof(recvBuffer), 0,
                                     reinterpret_cast<sockaddr*>(&addr), &addrLen);
        checkError(readCount, "Failed to read sock");
        state.sendAck = false;
        dissect(readCount);
        if (state.sendAck) encapsulate("");
        if (!secret.empty() && state.recvPacket) {
          std::cout << "Sending secret: " << secret << std::endl;
          encapsulate(secret);
          secret.clear();
        }
      }
    }
  }
}

void Session::dissect(ssize_t rdcnt) {
  auto payload = std::span{recvBuffer, recvBuffer + rdcnt};
  // TODO: NOTE
  // In following packet dissection code, we should set parameters if we are
  // receiving packets from remote
  // std::cout << "Dissecting packet " << std::endl;
  dissectIPv4(payload);
}

void Session::dissectIPv4(std::span<uint8_t> buffer) {
  // std::cout << "Dissecting IP packet" << std::endl;
  auto&& hdr = *reinterpret_cast<iphdr*>(buffer.data());
  // TODO:
  // Set `recvPacket = true` if we are receiving packet from remote
  state.recvPacket = (hdr.saddr == inet_addr(config.remote.c_str()));
  // std::cout << "Received packet from " << ipToString(hdr.saddr) << " and remote is " << config.remote << std::endl;
  // Track current IP id
  state.ipId = hdr.id;
  // Call dissectESP(payload) if next protocol is ESP
  // ihl is 32 bit long (4 bytes), so multiply 4
  auto payload = buffer.last(buffer.size() - hdr.ihl * 4);
  if (hdr.protocol == IPPROTO_ESP) {
    dissectESP(payload);
  } else if (hdr.protocol == IPPROTO_TCP) {
    dissectTCP(payload);
  }
}

void Session::dissectESP(std::span<uint8_t> buffer) {
  // std::cout << "Dissecting ESP packet" << std::endl;
  auto&& hdr = *reinterpret_cast<ESPHeader*>(buffer.data());
  int hashLength = config.aalg->hashLength();
  // Strip hash
  buffer = buffer.subspan(sizeof(ESPHeader), buffer.size() - sizeof(ESPHeader) - hashLength);
  std::vector<uint8_t> data;
  // Decrypt payload
  if (!config.ealg->empty()) {
    data = config.ealg->decrypt(buffer);
    buffer = std::span{data.data(), data.size()};
  }

  // TODO:
  // Track ESP sequence number
  state.espseq = hdr.seq;
  // Call dissectTCP(payload) if next protocol is TCP
  auto payload = buffer.last(buffer.size() - sizeof(ESPHeader));
  dissectTCP(payload);
}

void Session::dissectTCP(std::span<uint8_t> buffer) {
  // std::cout << "Dissecting TCP packet" << std::endl;
  auto&& hdr = *reinterpret_cast<tcphdr*>(buffer.data());
  // data offset is 32 bit long (4 bytes), so multiply 4
  auto length = hdr.doff << 2;
  auto payload = buffer.last(buffer.size() - length);
  // Track tcp parameters
  state.tcpseq = hdr.seq;
  state.tcpackseq = hdr.ack_seq;
  //std::cout << std::dec << "Receive seq: " << hdr.seq << " ack_seq: " << hdr.ack_seq << std::endl;
  // std::cout << "Receive src: " << ntohs(hdr.source) << " dst: " << ntohs(hdr.dest) << std::endl;
  state.srcPort = hdr.source;
  state.dstPort = hdr.dest;

  // Is ACK message?
  if (payload.empty()) return;
  // We only got non ACK when we receive secret, then we need to send ACK
  if (state.recvPacket) {
    std::cout << "Secret: " << std::string(payload.begin(), payload.end()) << std::endl;
    state.sendAck = true;
  }
}

void Session::encapsulate(const std::string& payload) {
  auto buffer = std::span{sendBuffer};
  std::fill(buffer.begin(), buffer.end(), 0);
  int totalLength = encapsulateIPv4(buffer, payload);
  // for (int i = 0; i < totalLength; i++) {
  //   std::cout << std::hex << (int)sendBuffer[i] << " ";
  //   if (i % 16 == 15) std::cout << std::endl;
  // }
  if ((sendto(sock, sendBuffer, totalLength, 0, reinterpret_cast<sockaddr*>(&addr), addrLen)) < 0) {
    std::cerr << "Failed to send packet" << std::endl;
    perror("sendto");
  } else {
    std::cout << "Sent packet" << std::endl;
  }
}

int Session::encapsulateIPv4(std::span<uint8_t> buffer, const std::string& payload) {
  // std::cout << "Encapsulating IP packet" << std::endl;
  auto&& hdr = *reinterpret_cast<iphdr*>(buffer.data());
  // TODO: Fill IP header
  hdr.version = 4;
  hdr.ihl = 5;
  hdr.ttl = 64;
  hdr.id = state.ipId;
  hdr.protocol = IPPROTO_ESP;
  hdr.frag_off = htons(0x4000);
  hdr.saddr = stringToIPv4(config.local).s_addr;
  hdr.daddr = stringToIPv4(config.remote).s_addr;
  auto nextBuffer = buffer.last(buffer.size() - sizeof(iphdr));

  int payloadLength = encapsulateESP(nextBuffer, payload);
  payloadLength += sizeof(iphdr);

  hdr.tot_len = htons(payloadLength);
  //hdr.check = 0;
  // for checksum
  iphdr* iphedr = reinterpret_cast<iphdr*>(&hdr);
  uint32_t sum = 0;
  auto buf = reinterpret_cast<const uint16_t*>(iphedr);
  for (int i = 0; i < iphedr->ihl * 2; i++) {
    sum += ntohs(buf[i]);
  }
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  hdr.check = ~htons(sum);
  return payloadLength;
}

int Session::encapsulateESP(std::span<uint8_t> buffer, const std::string& payload) {
  // std::cout << "Encapsulating ESP packet" << std::endl;
  auto&& hdr = *reinterpret_cast<ESPHeader*>(buffer.data());
  auto nextBuffer = buffer.last(buffer.size() - sizeof(ESPHeader));
  // TODO: Fill ESP header
  hdr.spi = config.spi;
  hdr.seq = htonl(state.espseq + 1);
  state.espseq++;
  int payloadLength = encapsulateTCP(nextBuffer, payload);

  auto endBuffer = nextBuffer.last(nextBuffer.size() - payloadLength);
  // TODO: Calculate padding size and do padding in `endBuffer`
  std::cout << "Payload length: " << std::dec << payloadLength << std::endl;
  // uint8_t padSize = (payloadLength / 4 + 1) * 4 - payloadLength - 4;
  uint8_t padSize = (payloadLength - 2) % 64 ? 64 - (payloadLength - 2) % 64 : 0;
  std::cout << "Padding size: " << (int)padSize << std::endl;
  payloadLength += padSize;
  // ESP trailer
  // 
  endBuffer[padSize] = padSize;
  // 
  endBuffer[padSize + 1] = IPPROTO_TCP;
  payloadLength += sizeof(ESPTrailer);
  // Do encryption
  if (!config.ealg->empty()) {
    auto result = config.ealg->encrypt(nextBuffer.first(payloadLength));
    std::copy(result.begin(), result.end(), nextBuffer.begin());
    payloadLength = result.size();
  }
  payloadLength += sizeof(ESPHeader);

  if (!config.aalg->empty()) {
    // TODO: Fill in config.aalg->hash()'s parameter
    auto result = config.aalg->hash(std::span{buffer.data(), payloadLength});
    std::copy(result.begin(), result.end(), buffer.begin() + payloadLength);
    payloadLength += result.size();
  }
  return payloadLength;
}

int Session::encapsulateTCP(std::span<uint8_t> buffer, const std::string& payload) {
  // std::cout << "Encapsulating TCP packet" << std::endl;
  auto&& hdr = *reinterpret_cast<tcphdr*>(buffer.data());
  if (!payload.empty()) hdr.psh = 1;
  // TODO: Fill TCP header
  hdr.ack = 1;
  hdr.doff = 5;
  // std::cout << "Src port: " << state.srcPort << " Dst port: " << state.dstPort << std::endl;
  hdr.dest = state.srcPort;
  hdr.source = state.dstPort;
  hdr.ack_seq = state.tcpseq;
  hdr.seq = state.tcpackseq;
  std::cout << "ack_seq: " << hdr.ack_seq << " seq: " << hdr.seq << std::endl;
  hdr.window = htons(502);
  auto nextBuffer = buffer.last(buffer.size() - sizeof(tcphdr));
  int payloadLength = 0;
  if (!payload.empty()) {
    std::copy(payload.begin(), payload.end(), nextBuffer.begin());
    payloadLength += payload.size();
  }
  // TODO: Update TCP sequence number
  //state.tcpseq = hdr.seq;
  //state.tcpseq++;
  payloadLength += sizeof(tcphdr);
  // TODO: Compute checksum
  //hdr.check = 0;
  iphdr* iphedr = reinterpret_cast<iphdr*>(buffer.data() - sizeof(iphdr));
  tcphdr* tcphedr = &hdr;
  uint32_t sum = 0;
  auto buf = reinterpret_cast<const uint16_t*>(iphedr);
  //std::cout << "IP header:\n"; 
  for (int i = 2; i < 6; i++) {
    //std::cout << std::hex << ntohs(buf[i]) << ' ';
    sum += ntohs(buf[i]);
  }
  sum += 0006; // add IPPROTO_TCP
  // std::cout << "payload size" << payload.size() << '\n';
  sum += sizeof(tcphdr) + payload.size();
  //std::cout << '\n';

  //std::cout << "TCP header:\n"; 
  buf = reinterpret_cast<const uint16_t*>(tcphedr);
  for (int i = 0; i < 10; i++) {
    //std::cout << std::hex << ntohs(buf[i]) << ' ';
    sum += ntohs(buf[i]);
  }
  //std::cout << '\n';
  //std::cout << "next buffer:\n";
  buf = reinterpret_cast<const uint16_t*>(nextBuffer.data());
  int len_buf = (payload.size()%2) ? payload.size()/2 + 1 : payload.size()/2;
  for (int i = 0; i < len_buf; i++) {
    //std::cout << std::hex << ntohs(buf[i]) << ' ';
    sum += ntohs(buf[i]);
  }
  //std::cout << '\n';
  // if (nextBuffer.size() % 2) {
  //   sum += (nextBuffer[nextBuffer.size() - 1] << 8);
  // }
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }
  hdr.check = htons(~sum);

  return payloadLength;
}
