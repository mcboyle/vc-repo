/*
 * v2format_cpp.cpp — link-proof for the C++ v2-format binding (src/Volume/V2FormatBinding.h) against the
 * REAL C module (Common/V2Format.o) + real Sha2.o. Same idea as hkf_cli_test.cpp: prove the C++ seam the
 * mount/create path will use actually compiles and calls the C module, reproducing the step-[85] anchors.
 *
 * Build (see build_and_verify.sh step [86]): g++ -std=c++14 -DVC_ENABLE_V2FORMAT this.cpp V2Format.o Sha2.o
 */
#include <cstdio>
#include <cstring>
#include <cstdint>

#include "Volume/V2FormatBinding.h"

using namespace VeraCrypt;

static int fails = 0;
static void check (const char *n, bool ok) { std::printf ("  %-52s %s\n", n, ok ? "PASS" : "FAIL"); if (!ok) fails++; }

int main ()
{
	unsigned char master[32], master2[32], ct0[64];
	unsigned char kmac_h[V2_KEY_LEN], tag0[V2_MAC_TAG_LEN];
	int i;
	for (i = 0; i < 32; i++) master[i] = (unsigned char) ((0x40 + i) & 0xff);
	std::memcpy (master2, master, 32); master2[0] ^= 0x01;
	for (i = 0; i < 64; i++) ct0[i] = (unsigned char) ((i * 7 + 3) & 0xff);

	/* drive the real C module through the binding's underlying calls to build sector 0's tag */
	V2FormatDeriveModeKey (master, 32, V2_MODE_HCTR2, kmac_h);
	V2FormatSectorTag (kmac_h, 0, ct0, 64, tag0);

	std::printf ("REF cpp_tag0 "); for (i = 0; i < V2_MAC_TAG_LEN; i++) std::printf ("%02x", tag0[i]); std::printf ("\n");

	int m_ok    = V2Format::DiscoverMode (master,  32, ct0, 64, tag0);
	int m_wrong = V2Format::DiscoverMode (master2, 32, ct0, 64, tag0);
	std::printf ("REF cpp_discover %d\n", m_ok);
	std::printf ("REF cpp_discover_wrong %d\n", m_wrong);
	check ("C++ binding discovers HCTR2 via the real C module", m_ok == V2_MODE_HCTR2 && V2Format::ModeIsV2 (m_ok));
	check ("C++ binding: wrong master key -> V2_MODE_NONE (v1)", m_wrong == V2_MODE_NONE && !V2Format::ModeIsV2 (m_wrong));

	V2Format::DataAreaSplit s = V2Format::SplitDataArea ((uint64_t) 1000 * 512, 512);
	std::printf ("REF cpp_split %llu %llu %d\n",
	             (unsigned long long) s.usableBytes, (unsigned long long) s.tableOffset, s.ok ? 1 : 0);
	check ("C++ binding SplitDataArea ok + usable==496128", s.ok && s.usableBytes == 496128 && s.tableOffset == 496128);
	check ("C++ binding rejects a too-small volume", !V2Format::SplitDataArea (512, 512).ok);

	std::printf ("\n%s\n", fails == 0 ? "V2 FORMAT C++ BINDING LINK-PROOF PASSED" : "V2 FORMAT C++ BINDING LINK-PROOF FAILED");
	return fails == 0 ? 0 : 1;
}
