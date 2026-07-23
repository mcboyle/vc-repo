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
	/* 000b (not reported) and reserved 011b..111b: cannot confirm the device is deniability-safe here,
	   but "no deterministic deallocate" is not itself a flash tell, so this axis is CLEAN and the
	   rotational axis (which already warns on any SSD) carries the flash decision. */
	return VC_FLASH_CLEAN;
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
	/* macOS: no reliable rotational flag exposed to userspace -> always warn. */
	(void) dev;
	return FlashProbeAggregate (VC_FLASH_WARN_ROTATIONAL, VC_FLASH_WARN_UNKNOWN, VC_FLASH_WARN_UNKNOWN);
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

#endif /* VC_ENABLE_FLASH_WARN */
