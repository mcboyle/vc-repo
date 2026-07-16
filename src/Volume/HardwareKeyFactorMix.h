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
}

#endif /* TC_HEADER_Volume_HardwareKeyFactorMix */
