/*
 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2026 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

/*
 * EncryptionModeHctr2 — the wide-block EncryptionMode shim over the proven src/Crypto/Hctr2.
 *
 * This is the second half of T2-4. `EncryptionModeAdiantum` (#35) was the first; ROADMAP named "the
 * HCTR2/Adiantum EncryptionMode classes" as the remaining work, and V2Format's mode enum is
 * `{V2_MODE_HCTR2 = 0, V2_MODE_ADIANTUM = 1, V2_MODE_NONE = -1}` — so until this class existed, the
 * v2 format's `V2FormatDiscoverMode` could never be shown to DISCRIMINATE between two modes, only to
 * return NONE on a wrong key. That is why this lands before the v2 mount-side work, not after.
 *
 * WHY WIDE-BLOCK AT ALL. XTS encrypts each 16-byte block independently under a tweak, so an adversary
 * comparing two disk snapshots learns WHICH 16-byte blocks changed inside a sector, and a targeted
 * ciphertext edit corrupts exactly one block. HCTR2 is a length-preserving tweakable SPRP over the whole
 * sector: every output byte depends on every input byte. Measured on the real class, a one-bit
 * plaintext change alters ~508 of 512 ciphertext bytes. (docs/HCTR2-SPEC.md, docs/THREAT-MODEL.md.)
 *
 * HCTR2 OR ADIANTUM — a hardware question, decided per volume (D-4).
 * HCTR2 runs its block cipher over the whole sector, so it wants AES-NI; Adiantum calls AES once per
 * sector and does the bulk in XChaCha12, so it is the non-AES-NI answer. D-4 records that the choice
 * MUST be a per-volume property stored in the header, never a per-machine runtime decision — otherwise
 * a volume created on an AES-NI machine will not open on one without it, and these users move media
 * between borrowed machines. Both modes therefore exist on every platform. Note this build's HCTR2 uses
 * the constant-time software AES (see Crypto/Hctr2.h), which is correct everywhere but slow without
 * AES-NI — that is the cost, not a defect.
 *
 * THE SAME ARCHITECTURAL MISMATCH AS ADIANTUM, STATED UP FRONT.
 * VeraCrypt's EncryptionMode is designed as "a mode wrapped around a CipherList" — XTS asks its Ciphers
 * to encrypt blocks. HCTR2 is not that shape: it bundles its own AES-256 (as block cipher AND as the
 * source of its POLYVAL key and L mask) and does not delegate to a Cipher. So this class accepts
 * SetCiphers() and IGNORES it. Consequences a reader must know:
 *   - "AES-HCTR2" and "Serpent-HCTR2" would be the SAME construction; cascades are meaningless here,
 *     and the mode must not be offered in the cipher-cascade UI as though it composed.
 *   - GetKeySize() is HCTR2's own 32 bytes, not a sum over Ciphers.
 *
 * Gated behind -DVC_ENABLE_HCTR2_MODE (which implies -DVC_ENABLE_HCTR2 and -DVC_ENABLE_CTAES). A build
 * without it is byte-for-byte stock, and HCTR2 is NOT offered as a volume format by default — like
 * Adiantum it is deliberately absent from EncryptionMode::GetAvailableModes() pending the v2 format
 * decision (D-10), because selecting it is a header change.
 */

#ifndef TC_HEADER_Volume_EncryptionModeHctr2
#define TC_HEADER_Volume_EncryptionModeHctr2

#if defined(VC_ENABLE_HCTR2_MODE)

#include "Platform/Platform.h"
#include "EncryptionMode.h"

extern "C" {
#include "Crypto/Hctr2.h"
}

namespace VeraCrypt
{
	class EncryptionModeHctr2 : public EncryptionMode
	{
	public:
		EncryptionModeHctr2 () { }
		virtual ~EncryptionModeHctr2 () { }

		virtual void Decrypt (uint8 *data, uint64 length) const;
		virtual void DecryptSectorsCurrentThread (uint8 *data, uint64 sectorIndex, uint64 sectorCount, size_t sectorSize) const;
		virtual void Encrypt (uint8 *data, uint64 length) const;
		virtual void EncryptSectorsCurrentThread (uint8 *data, uint64 sectorIndex, uint64 sectorCount, size_t sectorSize) const;

		virtual const SecureBuffer &GetKey () const { return Key; }
		virtual size_t GetKeySize () const { return Hctr2KeySize; }
		virtual wstring GetName () const { return L"HCTR2"; }
		virtual shared_ptr <EncryptionMode> GetNew () const { return shared_ptr <EncryptionMode> (new EncryptionModeHctr2); }

		/* Accepted for interface compatibility and deliberately unused — see the header comment. */
		virtual void SetCiphers (const CipherList &ciphers) { Ciphers = ciphers; }
		virtual void SetKey (const ConstBufferPtr &key);

		static const size_t Hctr2KeySize = 32;

	protected:
		void ProcessUnits (uint8 *data, uint64 length, uint64 startDataUnitNo, bool encrypt) const;
		void ProcessSectors (uint8 *data, uint64 sectorIndex, uint64 sectorCount, size_t sectorSize, bool encrypt) const;

		SecureBuffer Key;
		Hctr2Key     Schedule;

	private:
		EncryptionModeHctr2 (const EncryptionModeHctr2 &);
		EncryptionModeHctr2 &operator= (const EncryptionModeHctr2 &);
	};
}

#endif // VC_ENABLE_HCTR2_MODE
#endif // TC_HEADER_Volume_EncryptionModeHctr2
