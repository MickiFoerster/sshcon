#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sshcon/sshcon.h"

sshcon_status sshcon_connect(sshcon_connection *sc) {
  LIBSSH2_SESSION *session;
  unsigned long hostaddr;
  struct sockaddr_in sin;
  int sock;

  if (libssh2_init(0)) {
    return SSHCON_ERROR_LIBSSH2_INIT;
  }

  hostaddr = inet_addr(sc->hostname);
  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock == -1) {
      return SSHCON_ERROR_SOCKET;
  }
  sin.sin_family = AF_INET;
  sin.sin_port = htons(sc->port);
  sin.sin_addr.s_addr = hostaddr;
  int rc = connect(sock, (struct sockaddr *)(&sin),
                   sizeof(struct sockaddr_in));
  if (rc != 0) {
      close(sock);
      return SSHCON_ERROR_CONNECT;
  }

  session = libssh2_session_init();
  if (!session) {
      close(sock);
      return SSHCON_ERROR_LIBSSH2_SESSION_INIT;
  }

  // set session to non-blocking
  libssh2_session_set_blocking(session, 0);

  do {
      rc = libssh2_session_handshake(session, sock);
  } while (rc == LIBSSH2_ERROR_EAGAIN);
  if(rc) {
      return SSHCON_ERROR_LIBSSH2_SESSION_HANDSHAKE;
  }

  sc->socket = sock;
  sc->session = session;

  return SSHCON_OK;
}

void sshcon_disconnect(sshcon_connection *sc) {
    if (sc->session) {
        libssh2_session_disconnect(sc->session, "Normal Shutdown");
        libssh2_session_free(sc->session);
        sc->session = NULL;
    }

    if (sc->socket>0) {
        while (close(sc->socket)==EINTR)
            ;
        sc->socket = -1;
    }

    libssh2_exit();
}

sshcon_status sshcon_check_knownhosts(sshcon_connection *conn) {
  LIBSSH2_KNOWNHOSTS *nh;
  nh = libssh2_knownhost_init(conn->session);
  if (!nh) {
    return SSHCON_ERROR_KNOWNHOST_INIT;
  }

  char known_host_file[4096];
  const char *fingerprint;
  snprintf(known_host_file, sizeof(known_host_file), "%s/.ssh/known_hosts",
           getenv("HOME"));
  int rc = libssh2_knownhost_readfile(nh, known_host_file,
                                      LIBSSH2_KNOWNHOST_FILE_OPENSSH);
  if (rc <= 0) {
    fprintf(stderr, "error: reading known host file error %d\n", rc);
    libssh2_knownhost_free(nh);
    return SSHCON_ERROR_KNOWNHOST_FILE_READ;
  }

  size_t len;
  int type;
  fingerprint = libssh2_session_hostkey(conn->session, &len, &type);
  if (!fingerprint) {
    fprintf(stderr, "error: libssh2_session_hostkey() failed\n");
    libssh2_knownhost_free(nh);
    return SSHCON_ERROR_KNOWNHOST_GET_HOSTKEY;
  }

  struct libssh2_knownhost *host;
  int check = libssh2_knownhost_checkp(nh, 
                                       conn->hostname, 
                                       conn->port, 
                                       fingerprint, 
                                       len,
                                       LIBSSH2_KNOWNHOST_TYPE_PLAIN | LIBSSH2_KNOWNHOST_KEYENC_RAW, &host);
  fprintf(stderr, "DEBUG: check=%d\n", check);
  libssh2_knownhost_free(nh);

  switch (check) {
  case LIBSSH2_KNOWNHOST_CHECK_MATCH:
    return SSHCON_OK;
  case LIBSSH2_KNOWNHOST_CHECK_FAILURE:
    return SSHCON_ERROR_KNOWNHOST_CHECK_HOSTKEY_FAILURE;
  case LIBSSH2_KNOWNHOST_CHECK_NOTFOUND:
    return SSHCON_ERROR_KNOWNHOST_CHECK_HOSTKEY_NOTFOUND;
  case LIBSSH2_KNOWNHOST_CHECK_MISMATCH:
    return SSHCON_ERROR_KNOWNHOST_CHECK_HOSTKEY_MISMATCH;
  default:
    return SSHCON_ERROR_KNOWNHOST_CHECK_HOSTKEY;
  }
}

void sshcon_error_info(sshcon_connection *conn, sshcon_status err) {
    char *errmsg;
    int errlen;
    switch (err) {
        case SSHCON_ERROR_UNDEFINED:
            break;
        case SSHCON_OK:
            break;
        case SSHCON_ERROR_SOCKET:
            fprintf(stderr, "select() failed: (%d) %s\n", errno, strerror(errno));
            break;
        case SSHCON_ERROR_CONNECT:
            fprintf(stderr, "connect() failed: (%d) %s\n", errno, strerror(errno));
            break;
        case SSHCON_ERROR_LIBSSH2_INIT:
        case SSHCON_ERROR_LIBSSH2_SESSION_INIT:
        case SSHCON_ERROR_LIBSSH2_SESSION_HANDSHAKE:
        case SSHCON_ERROR_KNOWNHOST_INIT:
        case SSHCON_ERROR_KNOWNHOST_FILE_READ:
        case SSHCON_ERROR_KNOWNHOST_GET_HOSTKEY:
        case SSHCON_ERROR_KNOWNHOST_CHECK_HOSTKEY:
            libssh2_session_last_error(conn->session, &errmsg, &errlen, 0);
            fprintf(stderr, "sshcon error %d: (%d) %s\n", err, err, errmsg);
            break;
        case SSHCON_ERROR_KNOWNHOST_CHECK_HOSTKEY_FAILURE:
            fprintf(stderr, "error: check of the server's host key failed\n");
            break;
        case SSHCON_ERROR_KNOWNHOST_CHECK_HOSTKEY_NOTFOUND:
            fprintf(stderr, "error: server's host key was not found in locally stored known-hostkey-file\n");
            break;
        case SSHCON_ERROR_KNOWNHOST_CHECK_HOSTKEY_MISMATCH:
            fprintf(stderr, "error: server's host key does not match local stored one, thus possible man-in-the-middle attack\n");
            break;
    }
}
