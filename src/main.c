#include "sshcon/sshcon.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
  char hostname[16] = "192.168.0.15";
  uint16_t port = 22;
  const char *user = getenv("USER");

  if (argc>1) {
    strncpy(hostname, argv[1], sizeof(hostname));
  }
  if (argc>2) {
    port = atoi(argv[2]);
  }
  if (argc > 3) {
    user = argv[3];
  }

  sshcon_connection *conn = sshconn_Open(hostname, port, user, NULL);
  if (conn == NULL) {
    fprintf(stderr, "error in Open()\n");
    exit(1);
  }

  sshconn_Run(conn, "ls -l /home");
  sshconn_Run(conn, "hostname");
  sshconn_Run(conn, "exit 1");
  sshconn_Run(conn, "head /proc/cpuinfo");

  sshconn_Close(conn);

  return 0;
}

