#include "sshcon/sshcon.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
  sshcon_connection conn;
  memset(&conn, 0, sizeof(conn));
  conn.hostname = "192.168.0.15";
  conn.port = 22;

  sshcon_status err = sshcon_connect(&conn);
  if (err != SSHCON_OK) {
    sshcon_error_info(err);
    exit(1);
  }
  printf("connected\n");

  sshcon_disconnect(&conn);
  printf("disconnected\n");

  return 0;
}
