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

  std::map<string, string> arp_table;

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
  std::vector<std::string> victims;
  //std::string gwmac;
  // ip -> mac (map)
  for(std::map<string, string>::iterator it = arp_table.begin(); it != arp_table.end(); it++) {
    cout << it->first << '\t' << it->second << '\n';
    if(it->first != gwip) {
      victims.push_back(it->first);
      //gwmac = it->second;
    }
  }

  // create thread to send arp reply to spoof the gateway
  //thread t1(send_arp, ifname, victims[0], gwip);
  // create thread to send arp reply to spoof the victim

  return (EXIT_SUCCESS);
}
