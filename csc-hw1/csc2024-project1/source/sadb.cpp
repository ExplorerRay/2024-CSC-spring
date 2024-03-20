#include "sadb.h"

#include <arpa/inet.h>
#include <unistd.h>

#include <iomanip>
#include <iostream>


std::optional<ESPConfig> getConfigFromSADB() {
  // Allocate buffer
  std::vector<uint8_t> message(65536);
  sadb_msg msg{};
  // TODO: Fill sadb_msg (16 bytes)
  msg.sadb_msg_version = PF_KEY_V2;
  msg.sadb_msg_type = SADB_DUMP;
  msg.sadb_msg_satype = SADB_SATYPE_ESP;
  msg.sadb_msg_len = sizeof(msg) / 8; // in 64-bit word, 8 bytes
  msg.sadb_msg_pid = getpid();
  // add sadb_ext_type


  // TODO: Create a PF_KEY_V2 socket and write msg to it
  // refers to https://github.com/shichao-an/unpv13e/blob/master/key/printsadbmsg.c
  // and https://github.com/torvalds/linux/blob/master/include/uapi/linux/pfkeyv2.h
  int skt;
  checkError(skt = socket(PF_KEY, SOCK_RAW, PF_KEY_V2), "socket error");

  checkError(write(skt, &msg, sizeof(msg)), "write error");

  // Then read from socket to get SADB information
  int msglen, eof = 0;
  sadb_msg *rd_msg;
  sadb_ext *ext;
  sadb_sa *sa;
  sadb_key *key;
  sadb_address *addr;
  sockaddr_in *src_addr, *dst_addr;
  std::vector<uint8_t> key_data;

  while(eof == 0){
    checkError(msglen = read(skt, message.data(), message.size()), "read error");
    rd_msg = (sadb_msg *)message.data();
    std::cout << "type: " << (unsigned)rd_msg->sadb_msg_type << std::endl;
    std::cout << "seq: " << (unsigned)rd_msg->sadb_msg_seq << std::endl;
    std::cout << "len: " << rd_msg->sadb_msg_len << " " << msglen << std::endl;

    msglen -= sizeof(sadb_msg);
    ext = (sadb_ext *)(rd_msg + 1);
    std::cout << "ext len: " << ext->sadb_ext_len << std::endl;
    while(msglen > 0){
      std::cout << "ext type: " << ext->sadb_ext_type << std::endl;
      if(ext->sadb_ext_type == SADB_EXT_SA){ // == 1
        sa = (sadb_sa *)ext;
        std::cout << "sa spi: " << std::hex << htonl(sa->sadb_sa_spi) << std::dec << std::endl;
        std::cout << "auth alg: " << (unsigned)sa->sadb_sa_auth << std::endl;
        std::cout << "enc alg: " << (unsigned)sa->sadb_sa_encrypt << std::endl;
      }
      else if(ext->sadb_ext_type == SADB_EXT_ADDRESS_SRC){ // == 5
        addr = (sadb_address *)ext;

        src_addr = (sockaddr_in *)(addr + 1);
      }
      else if(ext->sadb_ext_type == SADB_EXT_ADDRESS_DST){ // == 6
        addr = (sadb_address *)ext;

        dst_addr = (sockaddr_in *)(addr + 1);
      }
      else if(ext->sadb_ext_type == SADB_EXT_KEY_AUTH){ // == 8
        key = (sadb_key *)ext;
        int bits;
        unsigned char *p;
        std::cout << "key exttype: " << (unsigned)key->sadb_key_exttype << std::endl;

        key_data.clear();
        printf(" %s key, %d bits: 0x",
          key->sadb_key_exttype == SADB_EXT_KEY_AUTH ?
          "Authentication" : "Encryption",
          key->sadb_key_bits);
        for (p = (unsigned char *)(key + 1), bits = key->sadb_key_bits;
            bits > 0; p++, bits -= 8){
            printf("%02x", *p);
            key_data.push_back(*p);
          }
        printf("\n");
      }
      msglen -= ext->sadb_ext_len << 3;
      ext = reinterpret_cast<sadb_ext*>(reinterpret_cast<char*>(ext) + (ext->sadb_ext_len << 3));
    }
    // ext_type 1 3 4 2 5 6 8 19

    if(rd_msg->sadb_msg_seq == 0){
      eof = 1;
    }
  }

  for(int i = 0; i < sizeof(message); i++){
    std::cout << std::hex << (unsigned)message[i] << " ";
    // if(i % 4 == 3){
    //   std::cout << " ";
    // }
  }
  std::cout << '\n';

  close(skt);

  // TODO: Set size to number of bytes in response message
  int size = sizeof(message);

  // Has SADB entry
  if (size != sizeof(sadb_msg)) {
    ESPConfig config{};
    // TODO: Parse SADB message
    config.spi = sa->sadb_sa_spi;
    //config.spi = htonl(0xfb170e3f);
    // auth algorithm:
    for (auto &c :std::span<uint8_t>{key_data}.subspan(16)) {
      std::cout << std::hex << (unsigned)c;
    }
    config.aalg = std::make_unique<ESP_AALG>((unsigned)sa->sadb_sa_auth, std::span<uint8_t>{key_data}.subspan(16));

    if((unsigned)sa->sadb_sa_encrypt == SADB_EALG_NONE){
      // No enc algorithm:
      config.ealg = std::make_unique<ESP_EALG>(SADB_EALG_NONE, std::span<uint8_t>{});
    }
    else{
      // Have enc algorithm:
      config.ealg = std::make_unique<ESP_EALG>((unsigned)sa->sadb_sa_encrypt, std::span<uint8_t>{key_data}.subspan(16));
    }
    config.ealg = std::make_unique<ESP_EALG>((unsigned)sa->sadb_sa_encrypt, std::span<uint8_t>{});
    // Source address:
    config.local = ipToString(src_addr->sin_addr.s_addr);
    // Destination address:
    config.remote = ipToString(dst_addr->sin_addr.s_addr);
    return config;
  }
  std::cerr << "SADB entry not found." << std::endl;
  return std::nullopt;
}

std::ostream &operator<<(std::ostream &os, const ESPConfig &config) {
  os << "------------------------------------------------------------" << std::endl;
  os << "AALG  : ";
  if (!config.aalg->empty()) {
    os << std::left << std::setw(30) << std::setfill(' ') << config.aalg->name();
    os << "HWACCEL: " << config.aalg->provider() << std::endl;
  } else {
    os << "NONE" << std::endl;
  }
  os << "EALG  : ";
  if (!config.ealg->empty()) {
    os << std::left << std::setw(30) << std::setfill(' ') << config.ealg->name();
    os << "HWACCEL: " << config.aalg->provider() << std::endl;
  } else {
    os << "NONE" << std::endl;
  }
  os << "Local : " << config.local << std::endl;
  os << "Remote: " << config.remote << std::endl;
  os << "------------------------------------------------------------";
  return os;
}
