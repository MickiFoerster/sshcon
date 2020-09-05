#include <stdbool.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <libssh2.h>

typedef struct {
    const char *hostname;
    uint16_t port;
    int socket ;
    LIBSSH2_SESSION *session;
    LIBSSH2_CHANNEL *channel;
} sshcon_connection;

static bool sshcon_connect(sshcon_connection *sc) {
    const char *commandline = "uptime";
    unsigned long hostaddr;
    struct sockaddr_in sin;
    int rc;
    int exitcode;
    char *exitsignal = (char *)"none";
    int bytecount = 0;

    rc = libssh2_init(0);
    if(rc != 0) {
        fprintf(stderr, "libssh2 initialization failed (%d)\n", rc);
        return false;
    }
 
    hostaddr = inet_addr(sc->hostname);
    sc->socket = socket(AF_INET, SOCK_STREAM, 0);
    sin.sin_family = AF_INET;
    sin.sin_port = htons(22);
    sin.sin_addr.s_addr = hostaddr;
    if(connect(sc->socket, (struct sockaddr*)(&sin),
                sizeof(struct sockaddr_in)) != 0) {
        fprintf(stderr, "failed to connect!\n");
        return -1;
    }

    // create non-blocking session
    session = libssh2_session_init();
    if (!session) {
      goto fatalerror;
    }
    libssh2_session_set_blocking(session, 0);
}
