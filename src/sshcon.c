#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>

#include <libssh2.h>
#include <libssh2_sftp.h>
#include "sshcon/sshcon.h"

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
  SSHCON_ERROR_CHANNEL_EXEC_COMMAND,
  SSHCON_ERROR_CHANNEL_READ,
  SSHCON_ERROR_CHANNEL_CLOSE,
  SSHCON_ERROR_CHANNEL_FREE,
  SSHCON_ERROR_SFTP_SESSION_INIT,
  SSHCON_ERROR_SFTP_OPEN,
  SSHCON_ERROR_SFTP_SESSION_LOCAL_FILE,
  SSHCON_ERROR_SFTP_SESSION_LOCAL_FSTAT,
  SSHCON_ERROR_SFTP_SESSION_ISDIR,
  SSHCON_ERROR_SFTP_SESSION_REMOTE_FILE,
  SSHCON_ERROR_SFTP_SESSION_REMOTE_WRITE,
  SSHCON_ERROR_SFTP_SESSION_LOCAL_READ,
} sshcon_status;

static sshcon_status sshcon_connect(sshcon_connection *conn);
static void sshcon_disconnect(sshcon_connection *conn);
static void sshcon_error_info(sshcon_connection *conn, sshcon_status err);
static sshcon_status sshconn_authenticate_with_agent(sshcon_connection *conn);
// static sshcon_status sshconn_authenticate_with_password(sshcon_connection *conn, const char *user, const char *password);
static sshcon_status sshconn_channel_open(sshcon_connection *conn);
static sshcon_status sshconn_channel_exec(sshcon_connection *conn,
                                          const char *cmd);
static sshcon_status sshconn_channel_read(sshcon_connection *conn);
static sshcon_status sshconn_channel_close(sshcon_connection *conn);
static int wait(sshcon_connection *conn);
static sshcon_status sshcon_sftp_upload(sshcon_connection *conn,
                                        const char *source_file_path,
                                        const char *target_file_path);

int sshconn_Run(sshcon_connection *conn, const char *cmd) {
  sshcon_status err;
  err = sshconn_channel_open(conn);
  if (err != SSHCON_OK) {
    sshcon_error_info(conn, err);
    exit(1);
  }
  printf("channel open\n");

  err = sshconn_channel_exec(conn, cmd);
  if (err != SSHCON_OK) {
    sshcon_error_info(conn, err);
    exit(1);
  }

  err = sshconn_channel_read(conn);
  if (err != SSHCON_OK) {
    sshcon_error_info(conn, err);
    exit(1);
  }

  err = sshconn_channel_close(conn);
  if (err != SSHCON_OK) {
    sshcon_error_info(conn, err);
    exit(1);
  }

  return conn->exitcode;
}

sshcon_connection *sshconn_Open(const char *hostname, uint16_t port,
                                const char *user, const char *password) {
  sshcon_connection tmpconn;
  memset(&tmpconn, 0, sizeof(tmpconn));
  tmpconn.hostname = hostname;
  tmpconn.port = port;
  tmpconn.username = user;

  sshcon_status err = sshcon_connect(&tmpconn);
  if (err != SSHCON_OK) {
    sshcon_error_info(&tmpconn, err);
    return NULL;
  }

  /*
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
     */

  err = sshconn_authenticate_with_agent(&tmpconn);
  if (err != SSHCON_OK) {
    sshcon_error_info(&tmpconn, err);
    return NULL;
  }

  sshcon_connection *conn = malloc(sizeof(sshcon_connection));
  memcpy(conn, &tmpconn, sizeof(sshcon_connection));

  return conn;
}

void sshconn_Close(sshcon_connection *conn) {
  sshcon_disconnect(conn);
  free(conn);
}

static sshcon_status sshcon_connect(sshcon_connection *conn) {
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
  int rc = connect(sock, (struct sockaddr *)(&sin), sizeof(struct sockaddr_in));
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
  if (rc) {
    return SSHCON_ERROR_LIBSSH2_SESSION_HANDSHAKE;
  }

  conn->socket = sock;
  conn->session = session;

  return SSHCON_OK;
}

static void sshcon_disconnect(sshcon_connection *conn) {
  if (conn == NULL) {
    return;
  }
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

#if 0
static sshcon_status sshcon_check_knownhosts(sshcon_connection *conn) {
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
#endif

static void sshcon_error_info(sshcon_connection *conn, sshcon_status err) {
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
    fprintf(stderr, "sshcon error %d: SSH handshake related error\n", err);
    break;
  case SSHCON_ERROR_KNOWNHOST_INIT:
  case SSHCON_ERROR_KNOWNHOST_FILE_READ:
  case SSHCON_ERROR_KNOWNHOST_GET_HOSTKEY:
  case SSHCON_ERROR_KNOWNHOST_CHECK_HOSTKEY:
    fprintf(stderr, "sshcon error %d: SSH known host checking related error\n",
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
  case SSHCON_ERROR_SFTP_SESSION_INIT:
  case SSHCON_ERROR_SFTP_OPEN:
  case SSHCON_ERROR_SFTP_SESSION_LOCAL_FILE:
  case SSHCON_ERROR_SFTP_SESSION_LOCAL_FSTAT:
  case SSHCON_ERROR_SFTP_SESSION_ISDIR:
  case SSHCON_ERROR_SFTP_SESSION_REMOTE_FILE:
  case SSHCON_ERROR_SFTP_SESSION_REMOTE_WRITE:
  case SSHCON_ERROR_SFTP_SESSION_LOCAL_READ:
    libssh2_session_last_error(conn->session, &errmsg, &errlen, 0);
    fprintf(stderr, "sshcon error %d: %s\n", err, errmsg);
    break;
  case SSHCON_ERROR_KNOWNHOST_CHECK_HOSTKEY_FAILURE:
    fprintf(stderr, "error: check of the server's host key failed\n");
    break;
  case SSHCON_ERROR_KNOWNHOST_CHECK_HOSTKEY_NOTFOUND:
    fprintf(stderr, "error: server's host key was not found in locally stored "
                    "known-hostkey-file\n");
    break;
  case SSHCON_ERROR_KNOWNHOST_CHECK_HOSTKEY_MISMATCH:
    fprintf(stderr, "error: server's host key does not match local stored one, "
                    "thus possible man-in-the-middle attack\n");
    break;
  }
}

static sshcon_status sshconn_authenticate_with_agent(sshcon_connection *conn) {
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

    while ((rc = libssh2_agent_userauth(agent, conn->username, identity)) ==
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

static sshcon_status sshconn_channel_exec(sshcon_connection *conn,
                                          const char *cmd) {
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

static sshcon_status sshconn_channel_read(sshcon_connection *conn) {
  ssize_t m, n;
  char buffer[0x4000];
  char stderr_buffer[0x4000];
  fprintf(stderr, "<-");
  for (;;) {
    /* loop until we block */
    do {
      n = libssh2_channel_read(conn->channel, buffer, sizeof(buffer));
      m = libssh2_channel_read_stderr(conn->channel, stderr_buffer,
                                      sizeof(stderr_buffer));
      if (n > 0) {
        for (int i = 0; i < n; ++i)
          fputc(buffer[i], stderr);
      }
      if (m > 0) {
        for (int i = 0; i < m; ++i)
          fputc(stderr_buffer[i], stderr);
      }
    } while (m > 0 || n > 0);

    if (n == LIBSSH2_ERROR_EAGAIN || m == LIBSSH2_ERROR_EAGAIN) {
      wait(conn);
      continue;
    }

    if (m == 0 && n == 0) {
      return SSHCON_OK;
    }

    return SSHCON_ERROR_CHANNEL_READ;
  }
}

static sshcon_status sshconn_channel_close(sshcon_connection *conn) {
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
  libssh2_channel_get_exit_signal(conn->channel, &exitsignal, NULL, NULL, NULL,
                                  NULL, NULL);

  if (exitsignal) {
    snprintf(conn->exitsignal, sizeof(conn->exitsignal), "%s", exitsignal);
    conn->exitcode = -1;
  } else {
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

static sshcon_status sshconn_channel_open(sshcon_connection *conn) {
  LIBSSH2_CHANNEL *channel;
  while ((channel = libssh2_channel_open_session(conn->session)) == NULL &&
         libssh2_session_last_error(conn->session, NULL, NULL, 0) ==
             LIBSSH2_ERROR_EAGAIN) {
    wait(conn);
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

bool sshconn_Upload(sshcon_connection *conn, const char *source_file_path,
                    const char *target_file_path) {
  if (!conn)
    return false;

  sshcon_status err;
  err = sshcon_sftp_upload(conn, source_file_path, target_file_path);
  if (err != SSHCON_OK) {
    sshcon_error_info(conn, err);
    return false;
  }
  return true;
}

typedef struct {
  sshcon_connection *conn;
  const char *source_file_path;
  const char *target_file_path;
  int local_file_fd;
  long local_file_mode;
  long local_file_size;
  LIBSSH2_SFTP *sftp_session;
  LIBSSH2_SFTP_HANDLE *sftp_handle;
} sshcon_sftp_session;

static sshcon_status sshcon_sftp_session_write(sshcon_sftp_session *sess) {
  char *errmsg;
  int errlen;
  long to_write = sess->local_file_size;

  do {
    char mem[4096];
    ssize_t n = read(sess->local_file_fd, mem, sizeof(mem));
    if (n > 0) {
      ssize_t m = 0;
      ssize_t written = 0;
      for (;;) {
        m = libssh2_sftp_write(sess->sftp_handle, mem + written, n - written);
        if (m == LIBSSH2_ERROR_EAGAIN) {
          wait(sess->conn);
          continue;
        } else if (m > 0) {
          written += m;
        } else if (m < 0) {
          libssh2_session_last_error(sess->conn->session, &errmsg, &errlen, 0);
          fprintf(stderr, "error: %s\n", errmsg);
          return SSHCON_ERROR_SFTP_SESSION_REMOTE_WRITE;
        }

        if (written == n) {
          break;
        }
      }
      to_write -= written;
    } else if (n < 0) {
      fprintf(stderr, "error: read failed: %s\n", strerror(errno));
      return SSHCON_ERROR_SFTP_SESSION_LOCAL_READ;
    }
  } while (to_write > 0);

  return SSHCON_OK;
}

static sshcon_status sshcon_sftp_session_open(sshcon_sftp_session *sess) {
  char *errmsg;
  int errlen;
  int fd = open(sess->source_file_path, O_RDONLY);
  if (fd == -1) {
    fprintf(stderr, "could not open local file: %s\n", strerror(errno));
    return SSHCON_ERROR_SFTP_SESSION_LOCAL_FILE;
  }
  sess->local_file_fd = fd;

  struct stat buf;
  int rc;
  rc = fstat(fd, &buf);
  if (rc != 0) {
    fprintf(stderr, "error: fstat() failed: %s\n", strerror(errno));
    return SSHCON_ERROR_SFTP_SESSION_LOCAL_FSTAT;
  }
  sess->local_file_size = buf.st_size;
  if (S_ISDIR(buf.st_mode)) {
    fprintf(stderr, "error: file to upload %s is a directory\n",
            sess->source_file_path);
    return SSHCON_ERROR_SFTP_SESSION_ISDIR;
  }

  long flags = 0;
  if (buf.st_mode & S_IRUSR)
    flags = flags | LIBSSH2_SFTP_S_IRUSR;
  if (buf.st_mode & S_IWUSR)
    flags = flags | LIBSSH2_SFTP_S_IWUSR;
  if (buf.st_mode & S_IXUSR)
    flags = flags | LIBSSH2_SFTP_S_IXUSR;
  if (buf.st_mode & S_IRGRP)
    flags = flags | LIBSSH2_SFTP_S_IRGRP;
  if (buf.st_mode & S_IWGRP)
    flags = flags | LIBSSH2_SFTP_S_IWGRP;
  if (buf.st_mode & S_IXGRP)
    flags = flags | LIBSSH2_SFTP_S_IXGRP;
  if (buf.st_mode & S_IROTH)
    flags = flags | LIBSSH2_SFTP_S_IROTH;
  if (buf.st_mode & S_IWOTH)
    flags = flags | LIBSSH2_SFTP_S_IWOTH;
  if (buf.st_mode & S_IXOTH)
    flags = flags | LIBSSH2_SFTP_S_IXOTH;
  sess->local_file_mode = flags;

  LIBSSH2_SFTP_HANDLE *sftp_handle = NULL;
  for (;;) {
    sftp_handle = libssh2_sftp_open(sess->sftp_session, sess->target_file_path,
                                    LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT |
                                        LIBSSH2_FXF_TRUNC,
                                    sess->local_file_mode);
    if (sftp_handle == NULL) {
      rc = libssh2_session_last_error(sess->conn->session, &errmsg, &errlen, 0);
      if (rc == LIBSSH2_ERROR_EAGAIN) {
        wait(sess->conn);
        continue;
      }
      libssh2_session_last_error(sess->conn->session, &errmsg, &errlen, 0);
      fprintf(stderr, "error: %s\n", errmsg);
      return SSHCON_ERROR_SFTP_SESSION_REMOTE_FILE;
    }
    break;
  }
  assert(sftp_handle);
  sess->sftp_handle = sftp_handle;

  return SSHCON_OK;
}

static sshcon_status sshcon_sftp_session_init(sshcon_sftp_session *sess) {
  LIBSSH2_SFTP *tmp_sftp_session;
  char *errmsg;
  int errlen;
  int rc;

  for (;;) {
    tmp_sftp_session = libssh2_sftp_init(sess->conn->session);
    if (tmp_sftp_session == NULL) {
      rc = libssh2_session_last_error(sess->conn->session, &errmsg, &errlen, 0);
      if (rc == LIBSSH2_ERROR_EAGAIN) {
        wait(sess->conn);
        continue;
      }
      fprintf(stderr, "error: %s\n", errmsg);
      return SSHCON_ERROR_SFTP_SESSION_INIT;
    }
    break;
  }

  sess->sftp_session = tmp_sftp_session;
  return SSHCON_OK;
}

static void sshcon_sftp_session_close(sshcon_sftp_session *sess) {
  if (sess->local_file_fd != -1)
    close(sess->local_file_fd);
  if (sess->sftp_handle != NULL)
    libssh2_sftp_close(sess->sftp_handle);
  if (sess->sftp_session != NULL)
    libssh2_sftp_shutdown(sess->sftp_session);
}

static sshcon_status sshcon_sftp_upload(sshcon_connection *conn,
                                        const char *source_file_path,
                                        const char *target_file_path) {
  sshcon_sftp_session sftp_session = {.conn = conn,
                                      .source_file_path = source_file_path,
                                      .target_file_path = target_file_path,
                                      .local_file_fd = -1,
                                      .local_file_mode = 0,
                                      .local_file_size = 0,
                                      .sftp_session = NULL,
                                      .sftp_handle = NULL};
  sshcon_status err;

  err = sshcon_sftp_session_init(&sftp_session);
  if (err != SSHCON_OK) {
    return err;
  }

  err = sshcon_sftp_session_open(&sftp_session);
  if (err != SSHCON_OK) {
    return err;
  }

  err = sshcon_sftp_session_write(&sftp_session);
  if (err != SSHCON_OK) {
    return err;
  }

  sshcon_sftp_session_close(&sftp_session);

  return SSHCON_OK;
}
