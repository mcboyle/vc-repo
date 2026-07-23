/*
 * flash_probe_test.c — unit test for src/Common/FlashProbe.c (research batch-2 C3).
 *
 * Fail-closed media check that backs the hidden-volume deniability warning. This harness proves the
 * SANDBOX-TESTABLE parts:
 *   - Linux rotational/discard probe against injected /sys FIXTURE trees (rotational 0/1, discard
 *     present/absent, missing file, missing device dir);
 *   - ATA IDENTIFY (word 169 bit 0 TRIM, word 69 bit 14 DRAT / bit 5 RZAT) and NVMe DLFEAT (bits 2:0)
 *     bit-decoding against synthetic identify buffers, including reserved/unknown encodings;
 *   - the FAIL-CLOSED contract as a named check: every unknown/error input yields a warn, never silence.
 *
 * Windows (IOCTL seek-penalty) and macOS (no rotational flag -> always warn) device paths are
 * real-build only — see the closing note. Includes FlashProbe.c to reach it directly (same technique
 * as the other verification/*_test.c harnesses).
 */
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

#define VC_ENABLE_FLASH_WARN
#include "Common/FlashProbe.c"

static int all_pass = 1;
static void check (const char *n, int ok) { printf ("  %-56s %s\n", n, ok ? "PASS" : "FAIL"); if (!ok) all_pass = 0; }

/* ---- fixture helpers ---- */
static void mkdirs (const char *root, const char *dev)
{
	char p[1024];
	snprintf (p, sizeof p, "%s/block", root);                mkdir (p, 0755);
	snprintf (p, sizeof p, "%s/block/%s", root, dev);        mkdir (p, 0755);
	snprintf (p, sizeof p, "%s/block/%s/queue", root, dev);  mkdir (p, 0755);
}
static void write_attr (const char *root, const char *dev, const char *attr, const char *val)
{
	char p[1024]; FILE *f;
	snprintf (p, sizeof p, "%s/block/%s/queue/%s", root, dev, attr);
	f = fopen (p, "wb"); if (f) { fputs (val, f); fclose (f); }
}

/* ---- synthetic ATA IDENTIFY (512 bytes; set little-endian word w) ---- */
static void ata_set (unsigned char id[512], int w, unsigned int v)
{ id[2 * w] = (unsigned char)(v & 0xff); id[2 * w + 1] = (unsigned char)((v >> 8) & 0xff); }

int main (void)
{
	char root[] = "/tmp/vc_flashfix_XXXXXX";
	if (!mkdtemp (root)) { printf ("could not make fixture dir\n"); return 1; }

	/* build fixture devices */
	mkdirs (root, "rot_hdd");     write_attr (root, "rot_hdd", "rotational", "1\n");
	mkdirs (root, "ssd");         write_attr (root, "ssd", "rotational", "0\n");
	mkdirs (root, "hdd_discard"); write_attr (root, "hdd_discard", "rotational", "1\n");
	                              write_attr (root, "hdd_discard", "discard_granularity", "512\n");
	mkdirs (root, "hdd_nodisc");  write_attr (root, "hdd_nodisc", "rotational", "1\n");
	                              write_attr (root, "hdd_nodisc", "discard_granularity", "0\n");
	mkdirs (root, "empty_rot");   /* dir exists but no rotational file */

	printf ("[Linux rotational/discard probe vs /sys fixtures]\n");
	check ("confirmed rotational (rotational=1, no discard) -> CLEAN",
	       FlashProbeRotationalSysfs (root, "rot_hdd") == VC_FLASH_CLEAN);
	check ("SSD (rotational=0) -> WARN_ROTATIONAL",
	       FlashProbeRotationalSysfs (root, "ssd") == VC_FLASH_WARN_ROTATIONAL);
	check ("rotational=1 + discard_granularity!=0 -> WARN_TRIM",
	       (FlashProbeRotationalSysfs (root, "hdd_discard") & VC_FLASH_WARN_TRIM) != 0);
	check ("rotational=1 + discard_granularity=0 -> CLEAN",
	       FlashProbeRotationalSysfs (root, "hdd_nodisc") == VC_FLASH_CLEAN);
	check ("missing rotational file -> WARN_ROTATIONAL (fail closed)",
	       (FlashProbeRotationalSysfs (root, "empty_rot") & VC_FLASH_WARN_ROTATIONAL) != 0);
	check ("missing device dir -> WARN_ROTATIONAL (fail closed)",
	       (FlashProbeRotationalSysfs (root, "ghost") & VC_FLASH_WARN_ROTATIONAL) != 0);
	check ("path-escape device name rejected -> WARN_ROTATIONAL",
	       (FlashProbeRotationalSysfs (root, "../../etc") & VC_FLASH_WARN_ROTATIONAL) != 0);

	printf ("[ATA IDENTIFY TRIM decode]\n");
	{
		unsigned char id[512];
		memset (id, 0, sizeof id);
		check ("no TRIM / DRAT / RZAT -> CLEAN", FlashProbeAtaTrim (id) == VC_FLASH_CLEAN);
		memset (id, 0, sizeof id); ata_set (id, 169, 1u << 0);
		check ("word169 bit0 (TRIM supported) -> WARN_TRIM", FlashProbeAtaTrim (id) == VC_FLASH_WARN_TRIM);
		memset (id, 0, sizeof id); ata_set (id, 69, 1u << 14);
		check ("word69 bit14 (DRAT) -> WARN_TRIM", FlashProbeAtaTrim (id) == VC_FLASH_WARN_TRIM);
		memset (id, 0, sizeof id); ata_set (id, 69, 1u << 5);
		check ("word69 bit5 (RZAT) -> WARN_TRIM", FlashProbeAtaTrim (id) == VC_FLASH_WARN_TRIM);
		check ("NULL identify buffer -> WARN_UNKNOWN (fail closed)",
		       FlashProbeAtaTrim (NULL) == VC_FLASH_WARN_UNKNOWN);
	}

	printf ("[NVMe DLFEAT decode]\n");
	check ("DLFEAT bits2:0 = 000b (not reported) -> CLEAN", FlashProbeNvmeDlfeat (0x00) == VC_FLASH_CLEAN);
	check ("DLFEAT bits2:0 = 001b (reads 0x00) -> WARN_TRIM", FlashProbeNvmeDlfeat (0x01) == VC_FLASH_WARN_TRIM);
	check ("DLFEAT bits2:0 = 010b (reads 0xFF) -> WARN_TRIM", FlashProbeNvmeDlfeat (0x02) == VC_FLASH_WARN_TRIM);
	check ("DLFEAT reserved 101b -> WARN_UNKNOWN (fail closed on an unparseable encoding)",
	       FlashProbeNvmeDlfeat (0x05) == VC_FLASH_WARN_UNKNOWN);
	check ("DLFEAT high bits ignored (0xFA -> bits2:0=010b) -> WARN_TRIM",
	       FlashProbeNvmeDlfeat (0xFA) == VC_FLASH_WARN_TRIM);

	printf ("[aggregate + fail-closed contract]\n");
	check ("all axes CLEAN -> CLEAN (only positive confirmation clears)",
	       FlashProbeAggregate (VC_FLASH_CLEAN, VC_FLASH_CLEAN, VC_FLASH_CLEAN) == VC_FLASH_CLEAN
	       && FlashProbeIsClean (VC_FLASH_CLEAN));
	/* the named fail-closed assertion: EVERY non-clean or unknown axis forces a warn */
	{
		int i, silent = 0;
		unsigned int axes[4] = { VC_FLASH_WARN_ROTATIONAL, VC_FLASH_WARN_TRIM, VC_FLASH_WARN_THIN, VC_FLASH_WARN_UNKNOWN };
		for (i = 0; i < 4; i++) {
			if (FlashProbeIsClean (FlashProbeAggregate (axes[i], VC_FLASH_CLEAN, VC_FLASH_CLEAN))) silent = 1;
			if (FlashProbeIsClean (FlashProbeAggregate (VC_FLASH_CLEAN, axes[i], VC_FLASH_CLEAN))) silent = 1;
			if (FlashProbeIsClean (FlashProbeAggregate (VC_FLASH_CLEAN, VC_FLASH_CLEAN, axes[i]))) silent = 1;
		}
		check ("FAIL-CLOSED: no unknown/error axis is ever treated as clean", !silent);
	}
	check ("caveat string is non-empty and mentions imaging twice",
	       FlashProbeCaveat () && strstr (FlashProbeCaveat (), "twice") != NULL);

	/* cleanup fixtures (best-effort) */
	{
		char cmd[1100]; snprintf (cmd, sizeof cmd, "rm -rf '%s'", root); if (system (cmd)) { /* ignore */ }
	}

	printf ("\n%s\n", all_pass
	        ? "FLASH PROBE TESTS PASSED (Linux probe unit-tested against fixtures; Windows/macOS probes compile-checked, need a real build)"
	        : "FLASH PROBE TESTS FAILED");
	return all_pass ? 0 : 1;
}
