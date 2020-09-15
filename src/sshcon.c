#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "sshcon/sshcon.h"

static int wait(sshcon_connection *conn);

sshcon_status sshcon_connect(sshcon_connection *conn) {
  LIBSSH2_SESSION *session;
  unsigned long hostaddr;
  struct sockaddr_in sin;
  int sock;

  if (libssh2_init(0)) {
    return SSHCON_ERROR_LIBSSH2_INIT;
  }

  hostaddr = inet_addr(conn->hostname);
  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock == -1) {
      return SSHCON_ERROR_SOCKET;
  }
  sin.sin_family = AF_INET;
  sin.sin_port = htons(conn->port);
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

  conn->socket = sock;
  conn->session = session;

  return SSHCON_OK;
}

void sshcon_disconnect(sshcon_connection *conn) {
  if (conn->session) {
    libssh2_session_disconnect(conn->session, "Normal Shutdown");
    libssh2_session_free(conn->session);
    conn->session = NULL;
  }

  if (conn->socket > 0) {
    while (close(conn->socket) == EINTR)
      ;
    conn->socket = -1;
  }

  libssh2_exit();
}

sshcon_status sshcon_check_knownhosts(sshcon_connection *conn) {
    fprintf(stderr, "Verify connection to remote host %s\n", conn->hostname);

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
    int check = libssh2_knownhost_checkp(
            nh, conn->hostname, conn->port, fingerprint, len,
            LIBSSH2_KNOWNHOST_TYPE_PLAIN | LIBSSH2_KNOWNHOST_KEYENC_RAW, &host);
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
          fprintf(stderr, "sshcon error %d: libssh2 init related error\n", err);
          break;
        case SSHCON_ERROR_LIBSSH2_SESSION_HANDSHAKE:
          fprintf(stderr, "sshcon error %d: SSH handshake related error\n",
                  err);
          break;
        case SSHCON_ERROR_KNOWNHOST_INIT:
        case SSHCON_ERROR_KNOWNHOST_FILE_READ:
        case SSHCON_ERROR_KNOWNHOST_GET_HOSTKEY:
        case SSHCON_ERROR_KNOWNHOST_CHECK_HOSTKEY:
          fprintf(stderr,
                  "sshcon error %d: SSH known host checking related error\n",
                  err);
          break;
        case SSHCON_ERROR_AGENT_INIT:
        case SSHCON_ERROR_AGENT_CONNECT:
        case SSHCON_ERROR_AGENT_LIST_IDENTITIES:
        case SSHCON_ERROR_AGENT_GET_IDENTITY:
        case SSHCON_ERROR_AGENT_AUTH_FAILED:
          fprintf(stderr, "sshcon error %d: SSH agent related error\n", err);
          break;
        case SSHCON_ERROR_CHANNEL_OPEN_SESSION:
        case SSHCON_ERROR_CHANNEL_EXEC_COMMAND:
        case SSHCON_ERROR_CHANNEL_READ:
        case SSHCON_ERROR_CHANNEL_CLOSE:
        case SSHCON_ERROR_CHANNEL_FREE:
          libssh2_session_last_error(conn->session, &errmsg, &errlen, 0);
          fprintf(stderr, "sshcon error %d: %s\n", err, errmsg);
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

sshcon_status sshconn_authenticate(sshcon_connection *conn) {
  LIBSSH2_AGENT *agent = libssh2_agent_init(conn->session);
  if (agent == NULL) {
    return SSHCON_ERROR_AGENT_INIT;
  }

  int rc = libssh2_agent_connect(agent);
  if (rc) {
    libssh2_agent_free(agent);
    return SSHCON_ERROR_AGENT_CONNECT;
  }

  rc = libssh2_agent_list_identities(agent);
  if (rc) {
    libssh2_agent_disconnect(agent);
    libssh2_agent_free(agent);
    return SSHCON_ERROR_AGENT_LIST_IDENTITIES;
  }

  struct libssh2_agent_publickey *identity = NULL;
  struct libssh2_agent_publickey *prev_identity = NULL;
  for (;;) {
    rc = libssh2_agent_get_identity(agent, &identity, prev_identity);
    if (rc == 1 /* end of list of public keys */) {
      libssh2_agent_disconnect(agent);
      libssh2_agent_free(agent);
      return SSHCON_ERROR_AGENT_AUTH_FAILED;
    }
    if (rc < 0 /* error */) {
      libssh2_agent_disconnect(agent);
      libssh2_agent_free(agent);
      return SSHCON_ERROR_AGENT_GET_IDENTITY;
    }

    while ((rc=libssh2_agent_userauth(agent, conn->username, identity)) ==
           LIBSSH2_ERROR_EAGAIN)
      ;
    if (rc == 0) {
      break; // authenticated
    }
    prev_identity = identity;
  }
  conn->agent = agent;

  return SSHCON_OK;
}

sshcon_status sshconn_channel_exec(sshcon_connection *conn, const char* cmd) {
  fprintf(stderr, "->%s\n", cmd);
  int rc;
  for (;;) {
      rc = libssh2_channel_exec(conn->channel, cmd);
      if (rc == LIBSSH2_ERROR_EAGAIN) {
        wait(conn);
        continue;
      }
      break;
  }
  if (rc != 0) {
      return SSHCON_ERROR_CHANNEL_EXEC_COMMAND;
  }

  return SSHCON_OK;
}

sshcon_status sshconn_channel_read(sshcon_connection *conn) {
  ssize_t m, n;
  char buffer[0x4000];
  char stderr_buffer[0x4000];
  fprintf(stderr, "<-");
  for (;;) {
      /* loop until we block */
      do {
          n = libssh2_channel_read(conn->channel, buffer, sizeof(buffer));
          m = libssh2_channel_read_stderr(conn->channel, stderr_buffer, sizeof(stderr_buffer));
          if (n > 0) {
              for (int i = 0; i < n; ++i)
                  fputc(buffer[i], stderr);
          } 
          if (m > 0) {
              for (int i = 0; i < m; ++i)
                  fputc(stderr_buffer[i], stderr);
          } 
      } while (m > 0 || n > 0);

      if ( n == LIBSSH2_ERROR_EAGAIN || m ==LIBSSH2_ERROR_EAGAIN) {
          wait(conn);
          continue;
      }

      if (m == 0 && n == 0) {
          return SSHCON_OK;
      }

      return SSHCON_ERROR_CHANNEL_READ;
  }
}

sshcon_status sshconn_channel_close(sshcon_connection *conn) {
    int exitcode = 127;
    int rc;
    char *exitsignal = (char *)"nosignal";
    do {
        rc = libssh2_channel_close(conn->channel);
    } while (rc == LIBSSH2_ERROR_EAGAIN);

    if (rc != 0) {
        return SSHCON_ERROR_CHANNEL_CLOSE;
    }

    while (libssh2_channel_wait_closed(conn->channel) == LIBSSH2_ERROR_EAGAIN) 
        ;
    exitcode = libssh2_channel_get_exit_status(conn->channel);
    libssh2_channel_get_exit_signal(conn->channel, &exitsignal, NULL, NULL, NULL, NULL, NULL);

    if (exitsignal) {
        snprintf(conn->exitsignal, sizeof(conn->exitsignal), "%s", exitsignal);
        conn->exitcode = -1;
    }
    else {
        conn->exitsignal[0] = '\0';
        conn->exitcode = exitcode;
    }

    do {
        rc = libssh2_channel_free(conn->channel);
    } while (rc == LIBSSH2_ERROR_EAGAIN);
    if (rc != 0) {
        return SSHCON_ERROR_CHANNEL_FREE;
    }
    conn->channel = NULL;

    return SSHCON_OK;
}

sshcon_status sshconn_channel_open(sshcon_connection *conn) {
    LIBSSH2_CHANNEL *channel;
    while ((channel = libssh2_channel_open_session(conn->session)) == NULL &&
           libssh2_session_last_error(conn->session, NULL, NULL, 0) ==
               LIBSSH2_ERROR_EAGAIN) {
        sleep(1);
      //wait(conn);
    }
    if (channel == NULL) {
        return SSHCON_ERROR_CHANNEL_OPEN_SESSION;
    }
    conn->channel = channel;

    return SSHCON_OK;
}

static int wait(sshcon_connection *conn) {
  struct timeval timeout;
  int rc;
  fd_set fd;
  fd_set *writefd = NULL;
  fd_set *readfd = NULL;
  int dir;

  timeout.tv_sec = 1;
  timeout.tv_usec = 0;

  FD_ZERO(&fd);
  FD_SET(conn->socket, &fd);

  /* now make sure we wait in the correct direction */
  dir = libssh2_session_block_directions(conn->session);
  if (dir & LIBSSH2_SESSION_BLOCK_INBOUND)
    readfd = &fd;
  if (dir & LIBSSH2_SESSION_BLOCK_OUTBOUND)
    writefd = &fd;

  rc = select(conn->socket + 1, readfd, writefd, NULL, &timeout);

  return rc;
}

