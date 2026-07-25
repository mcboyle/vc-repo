/*
 * netshare_server.c — minimal reference MR server speaking the SHIPPABLE compressed wire format.
 *
 * The older POC servers (netshare_transport_poc.c, netshare_tcp_poc.c) put the raw extended-coordinate
 * struct on the wire, so they CANNOT talk to src/Common/NetShare.c — which is the whole point of that
 * module: it speaks compressed 32-byte points. This is the counterpart, built on the same shipping code
 * (NetShareServerRespond), so the CLI test drives the real protocol rather than a lookalike.
 *
 *   --pubkey                 print S = s*G as 64 hex chars (what a user pins via --ns-server-key)
 *   --serve <port> [--wrong] answer Y = s*X for each 32-byte X, forever (--wrong uses a different s)
 *
 * Not a production server: no TLS, no rate limiting, no access control. It exists to prove the CLI's
 * enrol/unlock path end to end. A deployment would front this with a Tang-style HTTPS endpoint.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "Common/NetShare.h"

/* Deterministic server secrets so the test is reproducible. A real server keeps s in a KMS/HSM. */
static void server_seed (unsigned char s[32], int wrong)
{
	int i;
	for (i = 0; i < 32; i++) s[i] = (unsigned char) (wrong ? (0x55 * i + 2) : (0x11 * i + 3));
}

static int io_all (int fd, unsigned char *buf, size_t n, int writing)
{
	size_t done = 0;
	while (done < n)
	{
		ssize_t r = writing ? write (fd, buf + done, n - done) : read (fd, buf + done, n - done);
		if (r <= 0) return -1;
		done += (size_t) r;
	}
	return 0;
}

static int serve (int port, int wrong)
{
	unsigned char s[32];
	int ls, opt = 1;
	struct sockaddr_in a;

	server_seed (s, wrong);
	signal (SIGPIPE, SIG_IGN);

	ls = socket (AF_INET, SOCK_STREAM, 0);
	if (ls < 0) { perror ("socket"); return 1; }
	setsockopt (ls, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt);
	memset (&a, 0, sizeof a);
	a.sin_family = AF_INET; a.sin_addr.s_addr = htonl (INADDR_LOOPBACK); a.sin_port = htons ((uint16_t) port);
	if (bind (ls, (struct sockaddr *) &a, sizeof a) != 0) { perror ("bind"); return 1; }
	if (listen (ls, 8) != 0) { perror ("listen"); return 1; }
	fprintf (stderr, "netshare_server: listening on 127.0.0.1:%d%s\n", port, wrong ? " (WRONG secret)" : "");

	for (;;)
	{
		int c = accept (ls, NULL, NULL);
		unsigned char X[NETSHARE_POINT_LEN], Y[NETSHARE_POINT_LEN];
		if (c < 0) continue;
		if (io_all (c, X, sizeof X, 0) == 0)
		{
			/* The server sees only the blinded X. It cannot recover C or K from it. */
			if (NetShareServerRespond (s, X, Y) == NETSHARE_OK)
				io_all (c, Y, sizeof Y, 1);
		}
		close (c);
	}
}

int main (int argc, char **argv)
{
	int i, wrong = 0, port = 0, pubkey = 0;

	for (i = 1; i < argc; i++)
	{
		if (strcmp (argv[i], "--wrong") == 0) wrong = 1;
		else if (strcmp (argv[i], "--pubkey") == 0) pubkey = 1;
		else if (strcmp (argv[i], "--serve") == 0 && i + 1 < argc) port = atoi (argv[++i]);
	}

	if (pubkey)
	{
		unsigned char s[32], S[NETSHARE_POINT_LEN];
		server_seed (s, wrong);
		if (NetShareServerPublic (s, S) != NETSHARE_OK) { fprintf (stderr, "pubkey failed\n"); return 1; }
		for (i = 0; i < NETSHARE_POINT_LEN; i++) printf ("%02x", S[i]);
		printf ("\n");
		return 0;
	}
	if (port > 0) return serve (port, wrong);

	fprintf (stderr, "usage: %s --pubkey [--wrong] | --serve <port> [--wrong]\n", argv[0]);
	return 64;
}
