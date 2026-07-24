/*
 * FlashProbe.c — see FlashProbe.h. Fail-closed media check for hidden-volume deniability (batch-2 C3).
 *
 * Style: C, no VeraCrypt platform dependency, so the decoders compile and unit-test standalone
 * (verification/flash_probe_test.c) and drop into the Windows driver / Linux app alike. Gated behind
 * VC_ENABLE_FLASH_WARN.
 */

#include "FlashProbe.h"

#if defined(VC_ENABLE_FLASH_WARN)

#include <stdio.h>
#include <string.h>

/* little-endian u16 word `w` (0-based) of an ATA IDENTIFY buffer */
static unsigned int ata_word (const unsigned char *id512, int w)
{
	return (unsigned int) id512[2 * w] | ((unsigned int) id512[2 * w + 1] << 8);
}

unsigned int FlashProbeAtaTrim (const unsigned char *id512)
{
	unsigned int w169, w69;
	if (!id512)
		return VC_FLASH_WARN_UNKNOWN;                 /* no data -> fail closed */

	w169 = ata_word (id512, 169);   /* Data Set Management support; bit 0 = TRIM supported */
	w69  = ata_word (id512, 69);    /* Additional supported; bit 14 = DRAT, bit 5 = RZAT */

	/* TRIM in the data path OR a deterministic read-after-TRIM guarantee both let an examiner learn
	   which blocks are unallocated -> a hidden volume's free space becomes distinguishable. Warn on
	   any of them. */
	if ((w169 & (1u << 0)) || (w69 & (1u << 14)) || (w69 & (1u << 5)))
		return VC_FLASH_WARN_TRIM;
	return VC_FLASH_CLEAN;
}

unsigned int FlashProbeNvmeDlfeat (unsigned char dlfeat)
{
	unsigned int v = (unsigned int) (dlfeat & 0x07);  /* bits 2:0 = read behaviour after deallocate */
	if (v == 1u || v == 2u)                            /* 001b reads 0x00, 010b reads 0xFF: deterministic */
		return VC_FLASH_WARN_TRIM;
	if (v == 0u)                                       /* 000b: deallocate behaviour not reported */
		return VC_FLASH_CLEAN;                         /*   (no deterministic tell; rotational axis decides) */
	/* reserved 011b..111b: an encoding this decoder does not understand. Fail closed rather than assume
	   safe — the incoherent-but-reachable case is a device reporting rotational=1 AND a reserved DLFEAT
	   (a USB bridge / virtualization layer synthesizing both), where treating "unknown" as clean would
	   contradict the fail-closed contract this module exists to provide. */
	return VC_FLASH_WARN_UNKNOWN;
}

/* read a small sysfs attribute into buf (NUL-terminated, trailing newline stripped). returns 0 on
   success, non-zero on any error (missing / unreadable / empty). */
static int read_attr (const char *path, char *buf, size_t buflen)
{
	FILE *f;
	size_t n;
	if (buflen == 0)
		return 1;
	f = fopen (path, "rb");
	if (!f)
		return 1;                                     /* missing / unreadable -> caller fails closed */
	n = fread (buf, 1, buflen - 1, f);
	fclose (f);
	if (n == 0)
		return 1;
	buf[n] = '\0';
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' || buf[n - 1] == ' '))
		buf[--n] = '\0';
	return 0;
}

/* join <root>/block/<dev>/queue/<attr> into out; returns 0 on success. Rejects a dev containing '/'
   or ".." so a crafted device name cannot escape the injected root. */
static int queue_path (char *out, size_t outlen, const char *root, const char *dev, const char *attr)
{
	int r;
	if (!root || !dev || !attr)
		return 1;
	if (strchr (dev, '/') || strstr (dev, ".."))
		return 1;
	r = snprintf (out, outlen, "%s/block/%s/queue/%s", root, dev, attr);
	return (r < 0 || (size_t) r >= outlen) ? 1 : 0;
}

unsigned int FlashProbeRotationalSysfs (const char *sysroot, const char *dev)
{
	char path[1024], val[64];
	unsigned int warn = VC_FLASH_CLEAN;

	/* rotational: CLEAN only when the attribute reads exactly "1" */
	if (queue_path (path, sizeof path, sysroot, dev, "rotational") != 0
	    || read_attr (path, val, sizeof val) != 0)
		warn |= VC_FLASH_WARN_ROTATIONAL;             /* unknown -> fail closed */
	else if (strcmp (val, "1") != 0)
		warn |= VC_FLASH_WARN_ROTATIONAL;             /* "0" (SSD) or anything unexpected */

	/* discard in the data path: if discard_granularity exists and is non-zero, TRIM/discard is active */
	if (queue_path (path, sizeof path, sysroot, dev, "discard_granularity") == 0
	    && read_attr (path, val, sizeof val) == 0)
	{
		if (strcmp (val, "0") != 0)
			warn |= VC_FLASH_WARN_TRIM;               /* non-zero granularity => discard supported */
	}
	/* a MISSING discard_granularity is not evidence of safety, but on Linux the rotational flag already
	   carries the SSD decision; we do not additionally warn for its absence to avoid double-counting. */

	return warn;
}

unsigned int FlashProbeAggregate (unsigned int rotational, unsigned int trim, unsigned int thin)
{
	/* pure OR: the decision is CLEAN only if every axis came back CLEAN (0). Any warn bit — including
	   VC_FLASH_WARN_UNKNOWN from an axis the caller could not evaluate — makes the result warn. */
	return rotational | trim | thin;
}

int FlashProbeIsClean (unsigned int warn)
{
	return warn == VC_FLASH_CLEAN;
}

const char *FlashProbeCaveat (void)
{
	return "Even on rotational media, hidden-volume deniability fails against an adversary who images "
	       "the device twice (a changed-block classifier over the two snapshots detects the hidden "
	       "volume). Do not rely on deniability if the device may be imaged on more than one occasion.";
}

unsigned int FlashProbeMacDiskutil (const char *diskutilOutput)
{
	const char *p;
	if (!diskutilOutput)
		return VC_FLASH_WARN_UNKNOWN;                 /* no data -> fail closed */

	/* Find a line "Solid State: <value>" (diskutil pads with spaces). We scan case-insensitively for
	   the label, then read the first non-space token of its value. */
	for (p = diskutilOutput; *p; p++)
	{
		if ((p[0] == 'S' || p[0] == 's')
		    && strncmp (p, "Solid State", 11) != 0
		    && strncmp (p, "solid state", 11) != 0)
			continue;
		if (strncmp (p, "Solid State", 11) == 0 || strncmp (p, "solid state", 11) == 0)
		{
			const char *q = p + 11;
			while (*q == ' ' || *q == '\t' || *q == ':')   /* skip label punctuation/padding */
				q++;
			if ((q[0] == 'N' || q[0] == 'n') && (q[1] == 'o' || q[1] == 'O'))
				return VC_FLASH_CLEAN;                 /* "No" -> confirmed rotational on this axis */
			if ((q[0] == 'Y' || q[0] == 'y') && (q[1] == 'e' || q[1] == 'E'))
				return VC_FLASH_WARN_ROTATIONAL;       /* "Yes" -> SSD/flash */
			return VC_FLASH_WARN_UNKNOWN;              /* label present, value not understood */
		}
	}
	return VC_FLASH_WARN_UNKNOWN;                     /* no "Solid State" line at all -> fail closed */
}

int FlashProbeDeviceLeaf (const char *path, char *leafOut, size_t leafLen)
{
	const char *base;
	size_t n, i;
	if (!path || !leafOut || leafLen == 0)
		return 1;

	/* strip a leading "/dev/" (and any directory prefix) -> leaf name */
	base = strrchr (path, '/');
	base = base ? base + 1 : path;
	n = strlen (base);
	if (n == 0 || n >= leafLen)
		return 1;
	memcpy (leafOut, base, n + 1);

	/* strip the partition suffix. nvme/mmcblk partitions are "pN" (e.g. nvme0n1p3); sd/hd/vd/xvd
	   partitions are trailing digits (sda1). A suffix-less nvme/mmcblk base (nvme0n1) is left alone. */
	if (strstr (leafOut, "nvme") || strstr (leafOut, "mmcblk"))
	{
		i = n;
		while (i > 0 && leafOut[i - 1] >= '0' && leafOut[i - 1] <= '9')   /* trailing digits */
			i--;
		if (i > 1 && i < n && leafOut[i - 1] == 'p')                      /* preceded by 'p' => "pN" */
			leafOut[i - 1] = '\0';                                        /* drop "pN..." */
		/* else: no "pN" suffix (whole device) -> leave unchanged */
	}
	else
	{
		i = n;
		while (i > 0 && leafOut[i - 1] >= '0' && leafOut[i - 1] <= '9')
			i--;
		if (i > 0)                       /* keep at least the alpha stem; all-digit name is left as-is */
			leafOut[i] = '\0';
	}
	return leafOut[0] ? 0 : 1;
}

unsigned int FlashProbePath (const char *path)
{
	char leaf[128];
	if (FlashProbeDeviceLeaf (path, leaf, sizeof leaf) != 0)
		return VC_FLASH_WARN_ROTATIONAL | VC_FLASH_WARN_UNKNOWN;   /* cannot reduce -> fail closed */
	return FlashProbeDevice (leaf);
}

unsigned int FlashProbeDevice (const char *dev)
{
#if defined(__linux__)
	/* Linux: rotational + discard via sysfs. ATA/NVMe IDENTIFY would need a raw ioctl (SG_IO / NVMe
	   admin passthrough) that is real-media-only; the sysfs rotational flag already warns on any SSD,
	   so the sandbox-testable decision lives in FlashProbeRotationalSysfs. Thin/dedup/SMR under
	   device-mapper is not visible here -> fail closed by treating it as UNKNOWN. */
	unsigned int rot = FlashProbeRotationalSysfs ("/sys", dev);
	return FlashProbeAggregate (rot, VC_FLASH_CLEAN, VC_FLASH_WARN_UNKNOWN);
#elif defined(__APPLE__)
	/* macOS: `diskutil info <dev>` reports "Solid State: Yes/No". Run it and decode; a failed exec or
	   an unparseable value fails closed via FlashProbeMacDiskutil. */
	{
		char out[8192];
		size_t total = 0, got;
		FILE *pp;
		char cmd[256];
		int r = snprintf (cmd, sizeof cmd, "diskutil info %s 2>/dev/null", dev ? dev : "");
		if (r < 0 || (size_t) r >= sizeof cmd)
			return FlashProbeAggregate (VC_FLASH_WARN_ROTATIONAL, VC_FLASH_WARN_UNKNOWN, VC_FLASH_WARN_UNKNOWN);
		pp = popen (cmd, "r");
		if (!pp)
			return FlashProbeAggregate (VC_FLASH_WARN_ROTATIONAL, VC_FLASH_WARN_UNKNOWN, VC_FLASH_WARN_UNKNOWN);
		while (total + 1 < sizeof out && (got = fread (out + total, 1, sizeof out - 1 - total, pp)) > 0)
			total += got;
		out[total] = '\0';
		pclose (pp);
		return FlashProbeAggregate (FlashProbeMacDiskutil (out), VC_FLASH_CLEAN, VC_FLASH_WARN_UNKNOWN);
	}
#elif defined(_WIN32)
	/* Windows: IOCTL_STORAGE_QUERY_PROPERTY with StorageDeviceSeekPenaltyProperty; IncursSeekPenalty
	   == TRUE means rotational. Real-build only (needs <winioctl.h> + a device handle); fail closed
	   until wired. */
	(void) dev;
	return FlashProbeAggregate (VC_FLASH_WARN_ROTATIONAL, VC_FLASH_WARN_UNKNOWN, VC_FLASH_WARN_UNKNOWN);
#else
	(void) dev;
	return FlashProbeAggregate (VC_FLASH_WARN_ROTATIONAL, VC_FLASH_WARN_UNKNOWN, VC_FLASH_WARN_UNKNOWN);
#endif
}

const char *FlashProbeWarningText (unsigned int warn)
{
	if (FlashProbeIsClean (warn))
		return "This device appears to be rotational (magnetic) media. Hidden-volume deniability is "
		       "plausible here, BUT it still fails against an adversary who images the device on more "
		       "than one occasion (a changed-block classifier over two snapshots detects hidden-volume "
		       "writes). Do not rely on deniability if the device may be imaged more than once.";

	/* One combined, stable message covering the deniability-relevant reasons. We do not branch a distinct
	   string per bit (the reasons co-occur and the user action is the same); we name what was detected. */
	return "WARNING: this medium is NOT safe for a deniable hidden/decoy volume.\n"
	       "The device is a solid-state / flash device, is unknown, or supports TRIM/discard. On flash "
	       "media the flash translation layer (wear levelling, over-provisioning, TRIM) leaves "
	       "hidden-volume-creation residue in retired pages that chip-off recovery can read, and TRIM "
	       "reveals which blocks are unallocated \xE2\x80\x94 both break the assumption that free space is "
	       "indistinguishable from random. A hidden volume created here is NOT plausibly deniable against "
	       "a forensic examiner. Use rotational media (or accept that deniability does not hold), and note "
	       "that even rotational media does not survive repeated imaging (multi-snapshot attack).";
}

#endif /* VC_ENABLE_FLASH_WARN */
