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

#ifndef TC_HEADER_Volume_VolumeExceptions
#define TC_HEADER_Volume_VolumeExceptions

#include "Platform/Platform.h"

namespace VeraCrypt
{
	struct VolumeException : public Exception
	{
	protected:
		VolumeException ();
		VolumeException (const string &message);
		VolumeException (const string &message, const wstring &subject);
	};

#define TC_EXCEPTION(NAME) TC_EXCEPTION_DECL(NAME,VolumeException)

/* Keyslot duress marker (gated): thrown by Volume::Open when the matching keyslot carries
   KEYSLOT_FLAG_DURESS — the caller must run the safe duress action (dismount all + scrub, mount
   nothing) instead of mounting. Registered via the exception set so it serializes across the
   CoreService boundary like every other volume exception. Empty in a default build. */
#if defined(VC_ENABLE_KEYSLOTS)
#define TC_KEYSLOT_EXCEPTION_SET TC_EXCEPTION (KeyslotDuress);
#else
#define TC_KEYSLOT_EXCEPTION_SET
#endif

/* --v2-require assertion failures (gated). Nothing on disk marks a volume as v2 — that is the D-10
   deniability property, deliberate — so an adversary with write access can strip the per-sector MAC
   table and the volume then opens as v1 with authentication simply absent. Mount-time discovery stays
   non-fatal by default (an unreadable tail must not become a lockout), so the refusal has to be an
   assertion the caller opts into. Two distinct causes, because they want different advice:
   ...NotFound   = the tail read fine and no tag matched (never v2, or stripped)
   ...Unreadable = the tail could not be read at all (usually media damage)
   Registered via the exception set so they serialize across the CoreService boundary. Empty in a
   default build. */
#if defined(VC_ENABLE_V2FORMAT)
#define TC_V2REQUIRE_EXCEPTION_SET \
	TC_EXCEPTION (V2FormatRequiredNotFound); \
	TC_EXCEPTION (V2FormatRequiredUnreadable);
#else
#define TC_V2REQUIRE_EXCEPTION_SET
#endif

#undef TC_EXCEPTION_SET
#define TC_EXCEPTION_SET \
	TC_EXCEPTION (HigherVersionRequired); \
	TC_EXCEPTION (KeyfilePathEmpty); \
	TC_EXCEPTION (MissingVolumeData); \
	TC_EXCEPTION (MountedVolumeInUse); \
	TC_EXCEPTION (UnsupportedSectorSize); \
	TC_EXCEPTION (VolumeEncryptionNotCompleted); \
	TC_EXCEPTION (VolumeHostInUse); \
	TC_EXCEPTION (VolumeProtected); \
	TC_EXCEPTION (VolumeReadOnly); \
	TC_KEYSLOT_EXCEPTION_SET \
	TC_V2REQUIRE_EXCEPTION_SET

	TC_EXCEPTION_SET;

#undef TC_EXCEPTION
}

#endif // TC_HEADER_Volume_VolumeExceptions
