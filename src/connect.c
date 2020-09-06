#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include "sshcon/sshcon.h"

sshcon_status sshcon_connect(sshcon_connection *sc) {
  LIBSSH2_SESSION *session;
  unsigned long hostaddr;
  struct sockaddr_in sin;
  int sock;

  if (libssh2_init(0)) {
    return SSHCON_ERROR_LIBSSH2_INIT_FAILED;
  }

  hostaddr = inet_addr(sc->hostname);
  sock = socket(AF_INET, SOCK_STREAM, 0);
  sin.sin_family = AF_INET;
  sin.sin_port = htons(sc->port);
  sin.sin_addr.s_addr = hostaddr;
  int rc = connect(sc->socket, (struct sockaddr *)(&sin),
                   sizeof(struct sockaddr_in));
  if (rc != 0) {
    return SSHCON_ERROR_CONNECT_FAILED;
  }

  session = libssh2_session_init();
  if (!session) {
    return SSHCON_ERROR_LIBSSH2_SESSION_INIT_FAILED;
  }

  // set session to non-blocking
  libssh2_session_set_blocking(session, 0);

  sc->socket = sock;
  sc->session = session;

  return SSHCON_OK;
}

void sshcon_error_info(sshcon_status err) {
  switch (err) {
  case SSHCON_ERROR_UNDEFINED:
    break;
  case SSHCON_OK:
    break;
  case SSHCON_ERROR_LIBSSH2_INIT_FAILED:
    break;
  case SSHCON_ERROR_CONNECT_FAILED:
    break;
    fprintf(stderr, "connect() failed: %s\n", strerror(errno));
    break;
  case SSHCON_ERROR_LIBSSH2_SESSION_INIT_FAILED:
    break;
  }
}
