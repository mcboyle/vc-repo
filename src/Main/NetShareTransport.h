/*
 * NetShareTransport — POSIX TCP implementation of NetShareTransportFn, plus the enrol/unlock glue the
 * CLI calls. Deliberately wx-free and header-only so it can be unit-tested on its own, exactly like
 * Main/HardwareKeyFactorCli.h (see verification/netshare_cli_test.cpp).
 *
 * src/Common/NetShare.c is pure crypto with an injected transport seam — no sockets — so THIS is the
 * file that owns the platform I/O. That split is the same one KeyslotStore/KeyslotArea uses, and it is
 * what let the module be proven with no network at all (step [102]).
 *
 * TRUST-ON-FIRST-PROVISION IS NOT PAPERED OVER. Enrolment needs the server's public S. This does NOT
 * fetch S from the server: an active attacker at enrol time who substitutes their own S would own the
 * share thereafter, and the user would have no way to notice. So S must be supplied out of band and
 * pinned by the user (--ns-server-key). docs/NETWORK-SHARE-SPEC.md lists this under "Honest
 * limitations"; requiring the pin is how that limitation is actually addressed rather than restated.
 */

#ifndef TC_HEADER_Main_NetShareTransport
#define TC_HEADER_Main_NetShareTransport

#include <string>
#include <cstdio>
#include <cstring>
#include <cstdlib>

extern "C" {
#include "Common/NetShare.h"
}

#if defined(VC_ENABLE_NETSHARE)

#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>

namespace VeraCrypt
{
	struct NetShareEndpoint
	{
		std::string Host;
		int         Port;
		int         TimeoutSec;
		NetShareEndpoint () : Port (0), TimeoutSec (10) { }
	};

	inline bool NetShareParseEndpoint (const std::string &spec, NetShareEndpoint &ep, std::string &error)
	{
		std::string::size_type colon = spec.rfind (':');
		if (colon == std::string::npos || colon == 0 || colon + 1 >= spec.size())
		{
			error = "expected host:port";
			return false;
		}
		ep.Host = spec.substr (0, colon);
		const std::string portStr = spec.substr (colon + 1);
		for (std::string::size_type i = 0; i < portStr.size(); i++)
			if (portStr[i] < '0' || portStr[i] > '9') { error = "port must be numeric"; return false; }
		ep.Port = atoi (portStr.c_str());
		if (ep.Port <= 0 || ep.Port > 65535) { error = "port out of range"; return false; }
		return true;
	}

	inline bool NetShareHexToBytes (const std::string &hex, unsigned char *out, int expectLen, std::string &error)
	{
		if ((int) hex.size() != expectLen * 2) { error = "wrong length"; return false; }
		for (int i = 0; i < expectLen; i++)
		{
			int hi = -1, lo = -1;
			char ch = hex[2*i], cl = hex[2*i+1];
			if      (ch >= '0' && ch <= '9') hi = ch - '0';
			else if (ch >= 'a' && ch <= 'f') hi = ch - 'a' + 10;
			else if (ch >= 'A' && ch <= 'F') hi = ch - 'A' + 10;
			if      (cl >= '0' && cl <= '9') lo = cl - '0';
			else if (cl >= 'a' && cl <= 'f') lo = cl - 'a' + 10;
			else if (cl >= 'A' && cl <= 'F') lo = cl - 'A' + 10;
			if (hi < 0 || lo < 0) { error = "invalid hex digit"; return false; }
			out[i] = (unsigned char) ((hi << 4) | lo);
		}
		return true;
	}

	/*
	 * One request/response over TCP. Returns non-zero on ANY failure to complete the exchange, which is
	 * what lets NetShareRecover report NETSHARE_ERR_TRANSPORT instead of a bad share: an unreachable
	 * server must never be indistinguishable from a wrong key.
	 */
	inline int NetShareTcpTransport (void *ctx, const unsigned char *req, size_t reqLen,
	                                 unsigned char *resp, size_t respCap, size_t *respLen)
	{
		const NetShareEndpoint *ep = (const NetShareEndpoint *) ctx;
		struct addrinfo hints, *res = NULL, *ai;
		char portStr[16];
		int fd = -1, rc = -1;

		if (!ep) return -1;
		snprintf (portStr, sizeof portStr, "%d", ep->Port);

		memset (&hints, 0, sizeof hints);
		hints.ai_family = AF_UNSPEC;              /* v4 or v6 */
		hints.ai_socktype = SOCK_STREAM;
		if (getaddrinfo (ep->Host.c_str(), portStr, &hints, &res) != 0 || !res)
			return -1;

		for (ai = res; ai; ai = ai->ai_next)
		{
			fd = socket (ai->ai_family, ai->ai_socktype, ai->ai_protocol);
			if (fd < 0) continue;
			{
				struct timeval tv;
				tv.tv_sec = ep->TimeoutSec; tv.tv_usec = 0;
				setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
				setsockopt (fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
			}
			if (connect (fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
			close (fd); fd = -1;
		}
		freeaddrinfo (res);
		if (fd < 0) return -1;                     /* off-network: nothing listening / no route */

		{
			size_t done = 0;
			while (done < reqLen)
			{
				ssize_t n = write (fd, req + done, reqLen - done);
				if (n <= 0) { close (fd); return -1; }
				done += (size_t) n;
			}
		}
		{
			size_t want = NETSHARE_POINT_LEN, done = 0;
			if (respCap < want) { close (fd); return -1; }
			while (done < want)
			{
				ssize_t n = read (fd, resp + done, want - done);
				if (n <= 0) { close (fd); return -1; }   /* short reply is a transport failure */
				done += (size_t) n;
			}
			*respLen = done;
			rc = 0;
		}
		close (fd);
		return rc;
	}

	/* Read a credential file. Returns false with 'error' set; never conflates a missing file with a
	   failed unlock. */
	inline bool NetShareReadCred (const std::string &path, unsigned char *out, size_t outCap,
	                              size_t &outLen, std::string &error)
	{
		FILE *f = fopen (path.c_str(), "rb");
		if (!f) { error = "cannot open credential file: " + path; return false; }
		size_t n = fread (out, 1, outCap, f);
		int extra = fgetc (f);                        /* must be exactly NETSHARE_CRED_LEN bytes */
		fclose (f);
		if (extra != EOF) { error = "credential file is too long: " + path; return false; }
		if (n != NETSHARE_CRED_LEN) { error = "credential file has the wrong size: " + path; return false; }
		outLen = n;
		return true;
	}

	inline bool NetShareWriteCred (const std::string &path, const unsigned char *cred, std::string &error)
	{
		FILE *f = fopen (path.c_str(), "wb");
		if (!f) { error = "cannot write credential file: " + path; return false; }
		size_t n = fwrite (cred, 1, NETSHARE_CRED_LEN, f);
		int cerr = fclose (f);
		if (n != NETSHARE_CRED_LEN || cerr != 0) { error = "short write on credential file: " + path; return false; }
		return true;
	}

	/* Human-readable reason for a NetShare return code. The point of these strings is that an
	   unreachable server, a corrupt credential and a genuinely wrong answer are DIFFERENT messages —
	   the failure this whole module is shaped to avoid is all three collapsing into "wrong password". */
	inline std::string NetShareStrError (int rc)
	{
		switch (rc)
		{
		case NETSHARE_OK:              return "ok";
		case NETSHARE_ERR_PARAM:       return "invalid parameter";
		case NETSHARE_ERR_POINT:       return "the server returned a malformed point";
		case NETSHARE_ERR_TRANSPORT:   return "the network-share server could not be reached (off network?)";
		case NETSHARE_ERR_CRED:        return "the credential file is corrupt or of an unknown version";
		default:                       return "unknown error";
		}
	}
}

#endif /* VC_ENABLE_NETSHARE */
#endif /* TC_HEADER_Main_NetShareTransport */
