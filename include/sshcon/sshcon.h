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
  SSHCON_ERROR_AGENT_INIT,
  SSHCON_ERROR_AGENT_CONNECT,
  SSHCON_ERROR_AGENT_LIST_IDENTITIES,
  SSHCON_ERROR_AGENT_GET_IDENTITY,
  SSHCON_ERROR_AGENT_AUTH_FAILED,
  SSHCON_ERROR_CHANNEL_OPEN_SESSION,
} sshcon_status;

typedef struct {
    const char *hostname;
    uint16_t port;
    const char *username;
    int socket ;
    LIBSSH2_SESSION *session;
    LIBSSH2_AGENT *agent;
    LIBSSH2_CHANNEL *channel;

} sshcon_connection;

sshcon_status sshcon_connect(sshcon_connection *conn);
void sshcon_disconnect(sshcon_connection *conn);
sshcon_status sshcon_check_knownhosts(sshcon_connection *conn);
void sshcon_error_info(sshcon_connection *conn, sshcon_status err);
sshcon_status sshconn_authenticate(sshcon_connection *conn);
