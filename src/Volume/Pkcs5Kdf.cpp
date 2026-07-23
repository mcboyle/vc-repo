/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2026 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include "Common/Pkcs5.h"
#include "Platform/StringConverter.h"
#include "Pkcs5Kdf.h"
#include "VolumePassword.h"
#if !defined (WOLFCRYPT_BACKEND) && !defined (VC_DCS_DISABLE_ARGON2)
#include "argon2.h"
#endif

namespace VeraCrypt
{
	Pkcs5Kdf::Pkcs5Kdf ()
	{
	}

	Pkcs5Kdf::~Pkcs5Kdf ()
	{
	}

	int Pkcs5Kdf::DeriveKey (const BufferPtr &key, const VolumePassword &password, int pim, const ConstBufferPtr &salt) const
	{
		return DeriveKey (key, password, pim, salt, nullptr);
	}

	int Pkcs5Kdf::DeriveKey (const BufferPtr &key, const VolumePassword &password, int pim, const ConstBufferPtr &salt, long volatile *pAbortKeyDerivation) const
	{
		return DeriveKey (key, password, salt, GetIterationCount(pim), pAbortKeyDerivation);
	}

	int Pkcs5Kdf::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount, long volatile *pAbortKeyDerivation) const
	{
		(void) pAbortKeyDerivation;
		return DeriveKey (key, password, salt, iterationCount);
	}

	wstring Pkcs5Kdf::GetDerivationFailureMessage (int result) const
	{
		(void) result;
		return L"Key derivation failed";
	}

	shared_ptr <Pkcs5Kdf> Pkcs5Kdf::GetAlgorithm (const wstring &name)
	{
		foreach (shared_ptr <Pkcs5Kdf> kdf, GetAvailableAlgorithms())
		{
			if (kdf->GetName() == name || (kdf->IsArgon2() && name == L"Argon2id"))
				return kdf;
		}
		throw ParameterIncorrect (SRC_POS);
	}

	shared_ptr <Pkcs5Kdf> Pkcs5Kdf::GetAlgorithm (const Hash &hash)
	{
		foreach (shared_ptr <Pkcs5Kdf> kdf, GetAvailableAlgorithms())
		{
			if (kdf->IsArgon2())
				continue;

#if defined(VC_ENABLE_BALLOON_KDF)
			if (kdf->IsBalloon())
				continue;   /* Balloon's hash is SHA-256; never shadow Pkcs5HmacSha256 here */
#endif

			if (typeid (*kdf->GetHash()) == typeid (hash))
				return kdf;
		}

		throw ParameterIncorrect (SRC_POS);
	}

	Pkcs5KdfList Pkcs5Kdf::GetAvailableAlgorithms ()
	{
		Pkcs5KdfList l;

		l.push_back (shared_ptr <Pkcs5Kdf> (new Pkcs5HmacSha512 ()));
		l.push_back (shared_ptr <Pkcs5Kdf> (new Pkcs5HmacSha256 ()));
        #ifndef WOLFCRYPT_BACKEND
		l.push_back (shared_ptr <Pkcs5Kdf> (new Pkcs5HmacBlake2s ()));
                l.push_back (shared_ptr <Pkcs5Kdf> (new Pkcs5HmacWhirlpool ()));
		l.push_back (shared_ptr <Pkcs5Kdf> (new Pkcs5HmacStreebog ()));
		l.push_back (shared_ptr <Pkcs5Kdf> (new Pkcs5HmacSha3_512 ()));
        #ifndef VC_DCS_DISABLE_ARGON2
		l.push_back (shared_ptr <Pkcs5Kdf> (new Pkcs5Argon2 ()));
		l.push_back (shared_ptr <Pkcs5Kdf> (new Pkcs5HmacBlake2b ()));
        #endif
        #if defined(VC_ENABLE_BALLOON_KDF)
		l.push_back (shared_ptr <Pkcs5Kdf> (new Pkcs5Balloon ()));
        #endif
        #endif
		return l;
	}

	void Pkcs5Kdf::ValidateParameters (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const
	{
		if (key.Size() < 1 || password.Size() < 1 || salt.Size() < 1 || iterationCount < 1)
			throw ParameterIncorrect (SRC_POS);
	}

    #ifndef WOLFCRYPT_BACKEND
	int Pkcs5HmacBlake2s_Boot::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const
	{
		return DeriveKey (key, password, salt, iterationCount, nullptr);
	}

	int Pkcs5HmacBlake2s_Boot::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount, long volatile *pAbortKeyDerivation) const
	{
		ValidateParameters (key, password, salt, iterationCount);
		derive_key_blake2s (password.DataPtr(), (int) password.Size(), salt.Get(), (int) salt.Size(), iterationCount, key.Get(), (int) key.Size(), pAbortKeyDerivation);
		return 0;
	}

	int Pkcs5HmacBlake2s::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const
	{
		return DeriveKey (key, password, salt, iterationCount, nullptr);
	}

	int Pkcs5HmacBlake2s::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount, long volatile *pAbortKeyDerivation) const
	{
		ValidateParameters (key, password, salt, iterationCount);
		derive_key_blake2s (password.DataPtr(), (int) password.Size(), salt.Get(), (int) salt.Size(), iterationCount, key.Get(), (int) key.Size(), pAbortKeyDerivation);
		return 0;
	}
    #endif

	int Pkcs5HmacSha256_Boot::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const
	{
		return DeriveKey (key, password, salt, iterationCount, nullptr);
	}

	int Pkcs5HmacSha256_Boot::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount, long volatile *pAbortKeyDerivation) const
	{
		ValidateParameters (key, password, salt, iterationCount);
		derive_key_sha256 (password.DataPtr(), (int) password.Size(), salt.Get(), (int) salt.Size(), iterationCount, key.Get(), (int) key.Size(), pAbortKeyDerivation);
		return 0;
	}

	int Pkcs5HmacSha256::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const
	{
		return DeriveKey (key, password, salt, iterationCount, nullptr);
	}

	int Pkcs5HmacSha256::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount, long volatile *pAbortKeyDerivation) const
	{
		ValidateParameters (key, password, salt, iterationCount);
		derive_key_sha256 (password.DataPtr(), (int) password.Size(), salt.Get(), (int) salt.Size(), iterationCount, key.Get(), (int) key.Size(), pAbortKeyDerivation);
		return 0;
	}

	int Pkcs5HmacSha512::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const
	{
		return DeriveKey (key, password, salt, iterationCount, nullptr);
	}

	int Pkcs5HmacSha512::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount, long volatile *pAbortKeyDerivation) const
	{
		ValidateParameters (key, password, salt, iterationCount);
		derive_key_sha512 (password.DataPtr(), (int) password.Size(), salt.Get(), (int) salt.Size(), iterationCount, key.Get(), (int) key.Size(), pAbortKeyDerivation);
		return 0;
	}

    #ifndef WOLFCRYPT_BACKEND
	int Pkcs5HmacWhirlpool::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const
	{
		return DeriveKey (key, password, salt, iterationCount, nullptr);
	}

	int Pkcs5HmacWhirlpool::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount, long volatile *pAbortKeyDerivation) const
	{
		ValidateParameters (key, password, salt, iterationCount);
		derive_key_whirlpool (password.DataPtr(), (int) password.Size(), salt.Get(), (int) salt.Size(), iterationCount, key.Get(), (int) key.Size(), pAbortKeyDerivation);
		return 0;
	}
	
	int Pkcs5HmacStreebog::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const
	{
		return DeriveKey (key, password, salt, iterationCount, nullptr);
	}

	int Pkcs5HmacStreebog::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount, long volatile *pAbortKeyDerivation) const
	{
		ValidateParameters (key, password, salt, iterationCount);
		derive_key_streebog (password.DataPtr(), (int) password.Size(), salt.Get(), (int) salt.Size(), iterationCount, key.Get(), (int) key.Size(), pAbortKeyDerivation);
		return 0;
	}

	int Pkcs5HmacSha3_512::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const
	{
		return DeriveKey (key, password, salt, iterationCount, nullptr);
	}

	int Pkcs5HmacSha3_512::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount, long volatile *pAbortKeyDerivation) const
	{
		ValidateParameters (key, password, salt, iterationCount);
		derive_key_sha3_512 (password.DataPtr(), (int) password.Size(), salt.Get(), (int) salt.Size(), iterationCount, key.Get(), (int) key.Size(), pAbortKeyDerivation);
		return 0;
	}

	#ifndef VC_DCS_DISABLE_ARGON2
	int Pkcs5Argon2::DeriveKey (const BufferPtr &key, const VolumePassword &password, int pim, const ConstBufferPtr &salt) const
	{
		return DeriveKey (key, password, pim, salt, nullptr);
	}

	int Pkcs5Argon2::DeriveKey (const BufferPtr &key, const VolumePassword &password, int pim, const ConstBufferPtr &salt, long volatile *pAbortKeyDerivation) const
	{
		int iterationCount;
		int memoryCost;
#if defined(VC_ENABLE_ARGON2_PARAMS)
		// This is the derivation path used by the Linux/macOS application for BOTH create (VolumeCreator)
		// and mount (VolumeHeader::Decrypt). Resolve iterations + memory cost through the override-aware
		// path so an explicit --argon2-memory/-iterations actually shapes the volume key, not just the
		// self-test. Stock get_argon2_params ignores the override, which made those options no-ops here
		// (only parallelism leaked through, via Argon2GetParallelism() inside derive_key_argon2), so a
		// volume created with explicit params could not be reproduced/mounted. Parallelism stays consistent
		// because derive_key_argon2 reads Argon2GetParallelism() internally.
		{
			uint32 it = 0, mc = 0, par = 1;
			Argon2GetResolvedParams (pim, &it, &mc, &par);   // override when active, else stock PIM formula
			iterationCount = (int) it;
			memoryCost     = (int) mc;
		}
#else
		get_argon2_params (pim, &iterationCount, &memoryCost);
#endif

		ValidateParameters (key, password, salt, iterationCount);
		return derive_key_argon2 (password.DataPtr(), (int) password.Size(), salt.Get(), (int) salt.Size(), iterationCount, memoryCost, key.Get(), (int) key.Size(), pAbortKeyDerivation);
	}

	int Pkcs5Argon2::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const
	{
		(void) key;
		(void) password;
		(void) salt;
		(void) iterationCount;
		throw ParameterIncorrect (SRC_POS);
	}

	int Pkcs5Argon2::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount, long volatile *pAbortKeyDerivation) const
	{
		(void) pAbortKeyDerivation;
		return DeriveKey (key, password, salt, iterationCount);
	}

	wstring Pkcs5Argon2::GetDerivationFailureMessage (int result) const
	{
		return L"Argon2 key derivation failed: " + StringConverter::ToWide (argon2_error_message (result));
	}

	int Pkcs5Argon2::GetIterationCount (int pim) const
	{
		int iterationCount;
		int memoryCost;
		get_argon2_params (pim, &iterationCount, &memoryCost);
		return iterationCount;
	}

	int Pkcs5HmacBlake2b::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const
	{
		return DeriveKey (key, password, salt, iterationCount, nullptr);
	}

	int Pkcs5HmacBlake2b::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount, long volatile *pAbortKeyDerivation) const
	{
		ValidateParameters (key, password, salt, iterationCount);
		derive_key_blake2b (password.DataPtr(), (int) password.Size(), salt.Get(), (int) salt.Size(), iterationCount, key.Get(), (int) key.Size(), pAbortKeyDerivation);
		return 0;
	}
	#endif

	#if defined(VC_ENABLE_BALLOON_KDF)
	int Pkcs5Balloon::DeriveKey (const BufferPtr &key, const VolumePassword &password, int pim, const ConstBufferPtr &salt) const
	{
		return DeriveKey (key, password, pim, salt, nullptr);
	}

	int Pkcs5Balloon::DeriveKey (const BufferPtr &key, const VolumePassword &password, int pim, const ConstBufferPtr &salt, long volatile *pAbortKeyDerivation) const
	{
		uint32 tcost = 0, spaceKib = 0;
		BalloonGetResolvedParams (pim, &tcost, &spaceKib);

		ValidateParameters (key, password, salt, (int) tcost);
		return derive_key_balloon (password.DataPtr(), (int) password.Size(), salt.Get(), (int) salt.Size(), tcost, spaceKib, key.Get(), (int) key.Size(), pAbortKeyDerivation);
	}

	int Pkcs5Balloon::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const
	{
		(void) key;
		(void) password;
		(void) salt;
		(void) iterationCount;
		throw ParameterIncorrect (SRC_POS);
	}

	int Pkcs5Balloon::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount, long volatile *pAbortKeyDerivation) const
	{
		(void) pAbortKeyDerivation;
		return DeriveKey (key, password, salt, iterationCount);
	}

	int Pkcs5Balloon::GetIterationCount (int pim) const
	{
		uint32 tcost = 0, spaceKib = 0;
		BalloonGetResolvedParams (pim, &tcost, &spaceKib);
		return (int) tcost;
	}
	#endif
	
	int Pkcs5HmacStreebog_Boot::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const
	{
		return DeriveKey (key, password, salt, iterationCount, nullptr);
	}

	int Pkcs5HmacStreebog_Boot::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount, long volatile *pAbortKeyDerivation) const
	{
		ValidateParameters (key, password, salt, iterationCount);
		derive_key_streebog (password.DataPtr(), (int) password.Size(), salt.Get(), (int) salt.Size(), iterationCount, key.Get(), (int) key.Size(), pAbortKeyDerivation);
		return 0;
	}
    #endif
}
