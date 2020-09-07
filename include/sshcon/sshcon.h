#pragma once
#include <libssh2.h>
#include <stdint.h>

typedef enum {
  SSHCON_ERROR_UNDEFINED = 0,
  SSHCON_OK,
  SSHCON_ERROR_LIBSSH2_INIT,
  SSHCON_ERROR_SOCKET,
  SSHCON_ERROR_CONNECT,
  SSHCON_ERROR_LIBSSH2_SESSION_INIT,
  SSHCON_ERROR_LIBSSH2_SESSION_HANDSHAKE,
  SSHCON_ERROR_KNOWNHOST_INIT,
  SSHCON_ERROR_KNOWNHOST_FILE_READ,
  SSHCON_ERROR_KNOWNHOST_GET_HOSTKEY,
  SSHCON_ERROR_KNOWNHOST_CHECK_HOSTKEY,
  SSHCON_ERROR_KNOWNHOST_CHECK_HOSTKEY_FAILURE,
  SSHCON_ERROR_KNOWNHOST_CHECK_HOSTKEY_NOTFOUND,
  SSHCON_ERROR_KNOWNHOST_CHECK_HOSTKEY_MISMATCH,
} sshcon_status;

typedef struct {
    const char *hostname;
    uint16_t port;
    int socket ;
    LIBSSH2_SESSION *session;
    LIBSSH2_CHANNEL *channel;

} sshcon_connection;

sshcon_status sshcon_connect(sshcon_connection *sc);
void sshcon_disconnect(sshcon_connection *sc);
sshcon_status sshcon_check_knownhosts(sshcon_connection *sc);
void sshcon_error_info(sshcon_connection *sc, sshcon_status err);
