#include "utils.hpp"

using namespace std;

int main (int argc, char **argv) {
  if (argc != 2) {
    cout << "Usage: " << argv[0] << " <if_name>\n";
    return 1;
  }
  string ifname = argv[1];

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

  test_arp(ifname.c_str(), dst_ip);

  return (EXIT_SUCCESS);
}
