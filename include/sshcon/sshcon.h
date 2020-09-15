#pragma once
#include <libssh2.h>
#include <stdint.h>

typedef struct {
  const char *hostname;
  uint16_t port;
  const char *username;
  int socket;
  LIBSSH2_SESSION *session;
  LIBSSH2_AGENT *agent;
  LIBSSH2_CHANNEL *channel;
  char exitsignal[8];
  int exitcode;

} sshcon_connection;

sshcon_connection *sshconn_Open(const char *hostname, uint16_t port,
                                const char *user, const char *password);
void sshconn_Close(sshcon_connection *conn);
int sshconn_Run(sshcon_connection *conn, const char *cmd);
