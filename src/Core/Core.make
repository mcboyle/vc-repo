#
# Derived from source code of TrueCrypt 7.1a, which is
# Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
# by the TrueCrypt License 3.0.
#
# Modifications and additions to the original source code (contained in this file)
# and all other portions of this file are Copyright (c) 2013-2017 AM Crypto
# and are governed by the Apache License 2.0 the full text of which is
# contained in the file License.txt included in VeraCrypt binary and source
# code distribution packages.
#

OBJS :=
OBJS += CoreBase.o
OBJS += CoreException.o
OBJS += FatFormatter.o
OBJS += HostDevice.o
OBJS += MountOptions.o
OBJS += RandomNumberGenerator.o
OBJS += VolumeCreator.o
OBJS += Unix/CoreService.o
OBJS += Unix/CoreServiceRequest.o
OBJS += Unix/CoreServiceResponse.o
OBJS += Unix/CoreUnix.o
OBJS += Unix/$(PLATFORM)/Core$(PLATFORM).o
OBJS += Unix/$(PLATFORM)/Core$(PLATFORM).o
ifeq "$(PLATFORM)" "MacOSX"
OBJS += Unix/FreeBSD/CoreFreeBSD.o
endif

# Cross-platform memory-key scrub (opt-in via `make KEYSCRUB=1`; the -DVC_ENABLE_KEYSCRUB define is
# added globally by the top-level Makefile). A default build sets VC_ENABLE_KEYSCRUB=0, so none of
# these objects are compiled and the build stays byte-for-byte stock. This pulls in the scrub module,
# its C++ event manager, and the in-tree ChaCha/t1ha primitives the RAM-encryption transform reuses.
ifeq "$(VC_ENABLE_KEYSCRUB)" "1"
OBJS += KeyScrubEvents.o
OBJS += ../Common/KeyScrub.o
OBJS += ../Crypto/t1ha2.o
OBJS += ../Crypto/chacha256.o
OBJS += ../Crypto/chachaRng.o
endif

include $(BUILD_INC)/Makefile.inc
