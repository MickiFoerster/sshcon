#include "sshcon/sshcon.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
  sshcon_connection conn;
  memset(&conn, 0, sizeof(conn));
  conn.hostname = "192.168.0.15";
  conn.port = 22;
  conn.username = getenv("USER");

  if (argc>1) {
      conn.hostname = argv[1];
  }
  if (argc>2) {
      conn.port = atoi(argv[2]);
  }
  if (argc > 3) {
    conn.username = argv[3];
  }

  sshcon_status err = sshcon_connect(&conn);
  if (err != SSHCON_OK) {
    sshcon_error_info(&conn, err);
    exit(1);
  }
  printf("connected\n");

  err = sshcon_check_knownhosts(&conn);
  switch (err) {
      case SSHCON_OK:
          printf("Host is known\n");
          break;
      case SSHCON_ERROR_KNOWNHOST_CHECK_HOSTKEY_NOTFOUND:
          printf("Host is not known yet\n");
          break;
      case SSHCON_ERROR_KNOWNHOST_CHECK_HOSTKEY_MISMATCH:
        sshcon_error_info(&conn, err);
        fprintf(stderr, "warning: We continue nevertheless ...\n");
        break;
      default:
        sshcon_error_info(&conn, err);
        exit(1);
  }

  err = sshconn_authenticate(&conn);
  if (err != SSHCON_OK) {
    sshcon_error_info(&conn, err);
    exit(1);
  }
  printf("authenticated\n");

  err = sshconn_channel_open(&conn);
  if (err != SSHCON_OK) {
    sshcon_error_info(&conn, err);
    exit(1);
  }
  printf("channel open\n");

  err = sshconn_channel_exec(&conn, "hostname");
  if (err != SSHCON_OK) {
    sshcon_error_info(&conn, err);
    exit(1);
  }

  err = sshconn_channel_read(&conn);
  if (err != SSHCON_OK) {
    sshcon_error_info(&conn, err);
    exit(1);
  }

  sshconn_channel_close(&conn);

  sshcon_disconnect(&conn);
  printf("disconnected\n");

  return 0;
}
