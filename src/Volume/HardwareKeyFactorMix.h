/*
 * HardwareKeyFactorMix — C++ glue between the C HardwareKeyFactor module and the Linux/macOS
 * application's key-derivation path (Volume/, Core/). It produces a VolumePassword with the token's
 * response mixed in, so VolumeHeader::Decrypt (mount) and VolumeCreator (create) can require a
 * hardware token. See Common/HardwareKeyFactor.h for the design and Common/Volumes.c for the
 * equivalent C-path hooks used by the Windows driver.
 */

#ifndef TC_HEADER_Volume_HardwareKeyFactorMix
#define TC_HEADER_Volume_HardwareKeyFactorMix

#include <cstring>
#include "Platform/Platform.h"
#include "Platform/Memory.h"
#include "Volume/VolumePassword.h"

extern "C" {
#include "Common/HardwareKeyFactor.h"
}

namespace VeraCrypt
{
	/*
	 * If a hardware key factor is configured (g_hkfActiveConfig), returns a NEW password with the
	 * token's response (computed over 'salt', the header's PBKDF2 salt) mixed in exactly as a keyfile
	 * would be. If no factor is configured, returns a copy of the original password. Throws
	 * ExternalException if a configured token is missing or fails. Safe to call unconditionally.
	 */
	inline shared_ptr <VolumePassword> HKFMixPassword (const VolumePassword &password, const ConstBufferPtr &salt)
	{
		make_shared_auto (VolumePassword, result);

#if defined(VC_ENABLE_HKF)
		if (g_hkfActiveConfig && g_hkfActiveConfig->backend != HKF_BACKEND_NONE)
		{
			SecureBuffer buf (VolumePassword::MaxSize);
			size_t n = password.Size();
			if (n > buf.Size())
				n = buf.Size();
			if (n)
				Memory::Copy (buf.Ptr(), password.DataPtr(), n);

			int len = (int) n;
			int rc = HKFApplyIfConfigured (buf.Ptr(), &len, salt.Get(), (int) salt.Size());
			if (rc != HKF_OK)
				throw ExternalException (SRC_POS);   /* configured token missing or failed */

			result->Set (buf.Ptr(), (size_t) len);
			return result;
		}
#else
		(void) salt;
#endif

		result->Set (password);
		return result;
	}

#if defined(VC_ENABLE_HKF_MIX_V2)
	/*
	 * Mix a PRECOMPUTED factor response into a copy of 'password' under a specific mix version
	 * (HKF_MIX_V1 / HKF_MIX_V2). Used by the mount version-try loop so the token is queried once
	 * (via HKFComputeActiveResponse) and the same response is mixed under each version — no second
	 * hardware round-trip. 'responseLen == 0' returns a plain copy (no factor). See VolumeHeader::Decrypt.
	 */
	inline shared_ptr <VolumePassword> HKFMixPasswordWithResponse (const VolumePassword &password, const unsigned char *response, int responseLen, int version)
	{
		make_shared_auto (VolumePassword, result);

		if (responseLen > 0)
		{
			SecureBuffer buf (VolumePassword::MaxSize);
			size_t n = password.Size();
			if (n > buf.Size())
				n = buf.Size();
			if (n)
				Memory::Copy (buf.Ptr(), password.DataPtr(), n);

			int len = (int) n;
			HKFMixResponseIntoPasswordVer (version, buf.Ptr(), &len, response, responseLen);
			result->Set (buf.Ptr(), (size_t) len);
			return result;
		}

		result->Set (password);
		return result;
	}

	/*
	 * Compute the active factor over 'salt' and mix it into a copy of 'password' under 'version', in one
	 * call. Used by the CREATE path (single version, single compute — new volumes enroll under v2).
	 * Returns a plain copy if no factor is configured; throws ExternalException if a configured token
	 * is missing or fails.
	 */
	inline shared_ptr <VolumePassword> HKFMixPasswordVer (const VolumePassword &password, const ConstBufferPtr &salt, int version)
	{
		if (g_hkfActiveConfig && g_hkfActiveConfig->backend != HKF_BACKEND_NONE)
		{
			SecureBuffer resp (HKF_MAX_RESPONSE);
			int rlen = 0;
			if (HKFComputeActiveResponse (salt.Get(), (int) salt.Size(), resp.Ptr(), &rlen) != HKF_OK)
				throw ExternalException (SRC_POS);   /* configured token missing or failed */
			return HKFMixPasswordWithResponse (password, resp.Ptr(), rlen, version);
		}

		make_shared_auto (VolumePassword, result);
		result->Set (password);
		return result;
	}
#endif /* VC_ENABLE_HKF_MIX_V2 */
}

#endif /* TC_HEADER_Volume_HardwareKeyFactorMix */
