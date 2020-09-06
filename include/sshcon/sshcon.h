#pragma once
#include <libssh2.h>
#include <stdint.h>

typedef enum {
  SSHCON_ERROR_UNDEFINED = 0,
  SSHCON_OK,
  SSHCON_ERROR_LIBSSH2_INIT_FAILED,
  SSHCON_ERROR_CONNECT_FAILED,
  SSHCON_ERROR_LIBSSH2_SESSION_INIT_FAILED,
} sshcon_status;

typedef struct {
    const char *hostname;
    uint16_t port;
    int socket ;
    LIBSSH2_SESSION *session;
    LIBSSH2_CHANNEL *channel;

} sshcon_connection;

sshcon_status sshcon_connect(sshcon_connection *sc);
void sshcon_error_info(sshcon_status err);