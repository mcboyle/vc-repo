/*
 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2026 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

/*
 * EncryptionModeAdiantum — the wide-block EncryptionMode shim over the proven src/Crypto/Adiantum.
 *
 * The Adiantum ALGORITHM has been verified since step [91]: all 18 official google/adiantum KATs, both
 * directions, over the real Adiantum.o + AesCt.o + chacha256.o + Poly1305.o. What did not exist was any
 * `EncryptionMode` subclass, so there was no volume path to exercise it — `V2FormatBinding.h` records
 * itself as "BLOCKED ON the wide-block cipher mode classes" and docs/CANT-CLAIMS-AUDIT.md carried the
 * Adiantum row as a code task for that reason. This class is that missing piece.
 *
 * WHY WIDE-BLOCK AT ALL. XTS is a narrow-block mode: it encrypts each 16-byte block independently under
 * a tweak, so flipping one ciphertext byte corrupts exactly one 16-byte block and an adversary comparing
 * two snapshots learns WHICH 16-byte blocks changed inside a sector. Adiantum is length-preserving over
 * the whole sector: every output byte depends on every input byte, so a one-byte change randomises the
 * entire sector. That is a strictly stronger diffusion property for the snapshot adversary this fork
 * cares about (docs/ADIANTUM-SPEC.md, docs/THREAT-MODEL.md).
 *
 * ONE HONEST ARCHITECTURAL MISMATCH, STATED UP FRONT.
 * VeraCrypt's EncryptionMode is designed as "a mode wrapped around a CipherList" — XTS asks its Ciphers
 * to encrypt blocks. Adiantum is NOT that shape: it is a self-contained construction that bundles its
 * own primitives (constant-time AES-256 + XChaCha12 + NH/Poly1305) and does not delegate to a Cipher.
 * So this class accepts SetCiphers() and then IGNORES the cipher list. Consequences a reader must know:
 *   - "AES-Adiantum" and "Serpent-Adiantum" would be the SAME construction; cascades are meaningless
 *     here. The mode must not be offered in the cipher-cascade UI as though it composed.
 *   - GetKeySize() is Adiantum's own 32 bytes, not a sum over Ciphers.
 * This is a property of Adiantum, not a defect in the shim, but pretending the interface fits would be
 * the kind of overclaim docs/CANT-CLAIMS-AUDIT.md exists to catch.
 *
 * Gated behind -DVC_ENABLE_ADIANTUM_MODE (which implies -DVC_ENABLE_ADIANTUM). A build without it is
 * byte-for-byte stock, and Adiantum is NOT offered as a volume format by default — see the spec for the
 * on-disk/compatibility consequences of choosing it.
 */

#ifndef TC_HEADER_Volume_EncryptionModeAdiantum
#define TC_HEADER_Volume_EncryptionModeAdiantum

#if defined(VC_ENABLE_ADIANTUM_MODE)

#include "Platform/Platform.h"
#include "EncryptionMode.h"

extern "C" {
#include "Crypto/Adiantum.h"
}

namespace VeraCrypt
{
	class EncryptionModeAdiantum : public EncryptionMode
	{
	public:
		EncryptionModeAdiantum () { }
		virtual ~EncryptionModeAdiantum () { }

		virtual void Decrypt (uint8 *data, uint64 length) const;
		virtual void DecryptSectorsCurrentThread (uint8 *data, uint64 sectorIndex, uint64 sectorCount, size_t sectorSize) const;
		virtual void Encrypt (uint8 *data, uint64 length) const;
		virtual void EncryptSectorsCurrentThread (uint8 *data, uint64 sectorIndex, uint64 sectorCount, size_t sectorSize) const;

		virtual const SecureBuffer &GetKey () const { return Key; }
		virtual size_t GetKeySize () const { return AdiantumKeySize; }
		virtual wstring GetName () const { return L"Adiantum"; }
		virtual shared_ptr <EncryptionMode> GetNew () const { return shared_ptr <EncryptionMode> (new EncryptionModeAdiantum); }

		/* Accepted for interface compatibility and deliberately unused — see the header comment. */
		virtual void SetCiphers (const CipherList &ciphers) { Ciphers = ciphers; }
		virtual void SetKey (const ConstBufferPtr &key);

		static const size_t AdiantumKeySize = 32;

	protected:
		void ProcessUnits (uint8 *data, uint64 length, uint64 startDataUnitNo, bool encrypt) const;
		void ProcessSectors (uint8 *data, uint64 sectorIndex, uint64 sectorCount, size_t sectorSize, bool encrypt) const;

		SecureBuffer Key;
		AdiantumKey  Schedule;

	private:
		EncryptionModeAdiantum (const EncryptionModeAdiantum &);
		EncryptionModeAdiantum &operator= (const EncryptionModeAdiantum &);
	};
}

#endif // VC_ENABLE_ADIANTUM_MODE
#endif // TC_HEADER_Volume_EncryptionModeAdiantum
