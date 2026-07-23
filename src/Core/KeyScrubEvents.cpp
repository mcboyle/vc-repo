/*
 * KeyScrubEvents — see KeyScrubEvents.h for the design and the verification boundary.
 */

#include "KeyScrubEvents.h"

#if defined(VC_ENABLE_KEYSCRUB)

#include <time.h>
#include <string.h>
#include <stdio.h>

extern "C" {
#include "Common/KeyScrub.h"
#include "Common/HardwareKeyFactor.h"
}

namespace VeraCrypt
{
	KeyScrubManager &KeyScrubManager::Instance ()
	{
		static KeyScrubManager instance;
		return instance;
	}

	KeyScrubManager::KeyScrubManager ()
		: Enabled (false), IdleTimeoutSeconds (0), LastActivity (0),
		  StopThreads (false), IdleThreadStarted (false)
	{
		pthread_mutex_init (&Lock, 0);
	}

	KeyScrubManager::~KeyScrubManager ()
	{
		Shutdown ();
		pthread_mutex_destroy (&Lock);
	}

	double KeyScrubManager::MonotonicNow () const
	{
		struct timespec ts;
#if defined(CLOCK_MONOTONIC)
		if (clock_gettime (CLOCK_MONOTONIC, &ts) == 0)
			return (double) ts.tv_sec + (double) ts.tv_nsec / 1e9;
#endif
		return (double) time (0);
	}

	/*
	 * CSPRNG seed for the RAM-encryption key-derivation area. The kernel getrandom()/urandom is used
	 * directly here so the scrub module has no dependency on VeraCrypt's RandomNumberGenerator (which
	 * is not yet started at the point Enable() runs). This only seeds the *obfuscation* key for keys
	 * at rest in RAM; it is not used to derive any on-disk key, so it never affects volume material.
	 */
	void KeyScrubManager::RandSeed (unsigned char *out, size_t len)
	{
		FILE *f = fopen ("/dev/urandom", "rb");
		if (f)
		{
			size_t got = fread (out, 1, len, f);
			fclose (f);
			if (got == len)
				return;
		}
		/* last-resort fallback: never for on-disk keys, only to vary the in-RAM obfuscation key */
		double t = 0;
		struct timespec ts;
#if defined(CLOCK_MONOTONIC)
		clock_gettime (CLOCK_MONOTONIC, &ts);
		t = (double) ts.tv_sec + (double) ts.tv_nsec;
#endif
		for (size_t i = 0; i < len; i++)
			out[i] = (unsigned char) ((((unsigned long) t) >> (i & 7)) ^ (i * 131u));
	}

	void KeyScrubManager::Enable (int idleTimeoutSeconds)
	{
		pthread_mutex_lock (&Lock);
		if (!Enabled)
		{
			VcKeyMemoryLockdown ();   // no swap / no core / no ptrace, before any secret is derived

			// Loud warning for the exposures mlock cannot close (ROI item 11): an active swap area or
			// suspend-to-disk still pushes key material to persistent storage. Printed once at enable.
			{
				int exposure = VcSwapHibernateStatus ();
				if (exposure & VC_HIBERNATE_SWAP_ACTIVE)
					fprintf (stderr, "WARNING: an active swap area is present — key material paged out "
					                 "before mlock (or by another process) can reach unencrypted disk. "
					                 "Encrypt swap or run `swapoff` while volumes are mounted.\n");
				if (exposure & VC_HIBERNATE_SUPPORTED)
					fprintf (stderr, "WARNING: hibernation (suspend-to-disk) is available on this system "
					                 "— it snapshots ALL of RAM, mlocked pages included, to disk. Disable "
					                 "hibernation while volumes are mounted (see docs/MEMORY-SCRUB.md).\n");
			}

			VcKsRamProtectInit (&KeyScrubManager::RandSeed);
			Enabled = true;
			IdleTimeoutSeconds = idleTimeoutSeconds;
			LastActivity = MonotonicNow ();
		}
		pthread_mutex_unlock (&Lock);

		if (idleTimeoutSeconds > 0)
			StartIdleMonitor ();
		StartScreenLockMonitor ();
		StartDeviceMonitor ();
	}

	void KeyScrubManager::ScrubNow (const char *reason)
	{
		(void) reason;
		VcScrubAll ();
		HKFScrubActiveConfig ();
	}

	void KeyScrubManager::NotifyActivity ()
	{
		pthread_mutex_lock (&Lock);
		LastActivity = MonotonicNow ();
		pthread_mutex_unlock (&Lock);
	}

	void KeyScrubManager::OnVolumeDismounted ()   { ScrubNow ("unmount"); }
	void KeyScrubManager::OnScreenLocked ()       { ScrubNow ("screen-lock"); }
	void KeyScrubManager::OnNewDeviceConnected () { ScrubNow ("new-device-connect"); }

	// -------------------------------------------------------------------- idle timeout (portable)

	void *KeyScrubManager::IdleThreadEntry (void *selfPtr)
	{
		KeyScrubManager *self = (KeyScrubManager *) selfPtr;
		while (!self->StopThreads)
		{
			struct timespec req; req.tv_sec = 1; req.tv_nsec = 0;
			nanosleep (&req, 0);
			if (self->StopThreads)
				break;

			pthread_mutex_lock (&self->Lock);
			double idle = self->MonotonicNow () - self->LastActivity;
			int timeout = self->IdleTimeoutSeconds;
			pthread_mutex_unlock (&self->Lock);

			if (timeout > 0 && idle >= (double) timeout)
			{
				self->ScrubNow ("idle-timeout");
				self->NotifyActivity ();   // scrub once per idle period, not every second
			}
		}
		return 0;
	}

	void KeyScrubManager::StartIdleMonitor ()
	{
		pthread_mutex_lock (&Lock);
		bool start = !IdleThreadStarted;
		IdleThreadStarted = true;
		pthread_mutex_unlock (&Lock);
		if (start)
			pthread_create (&IdleThread, 0, &KeyScrubManager::IdleThreadEntry, this);
	}

	// ----------------------------------------------------------- screen lock (platform glue)
	//
	// Real implementation subscribes to the desktop's lock signal and calls OnScreenLocked().
	// Compiled behind VC_KEYSCRUB_LOGIND (Linux, sd-bus) / __APPLE__ (macOS). Cannot be exercised in
	// a sandbox — VALIDATE ON A REAL SESSION. See docs/MEMORY-SCRUB.md.

	void KeyScrubManager::StartScreenLockMonitor ()
	{
#if defined(VC_KEYSCRUB_LOGIND)
		// Sketch (requires -lsystemd): open a user-bus match on
		//   type='signal',interface='org.freedesktop.login1.Session',member='Lock'
		// and on PrepareForSleep(true); dispatch on a helper thread; call OnScreenLocked().
		// Left to the packager to wire to their event loop; intentionally not linked by default.
		StartLogindScreenLockMonitor ();
#elif defined(__APPLE__) && defined(VC_KEYSCRUB_MACOS_LOCK)
		// Sketch: CFNotificationCenterAddObserver for "com.apple.screenIsLocked" -> OnScreenLocked().
		StartMacScreenLockMonitor ();
#else
		// Not compiled in: the screen-lock trigger is inert in this build.
		fprintf (stderr, "KeyScrub: screen-lock monitor not compiled in "
		                 "(build with VC_KEYSCRUB_LOGIND / VC_KEYSCRUB_MACOS_LOCK; validate on a real session)\n");
#endif
	}

	// ----------------------------------------------------- new device connect (platform glue)
	//
	// Real implementation monitors hotplug and calls OnNewDeviceConnected(). Compiled behind
	// VC_KEYSCRUB_UDEV (Linux, libudev) / __APPLE__ (macOS IOKit). VALIDATE ON A REAL SESSION.

	void KeyScrubManager::StartDeviceMonitor ()
	{
#if defined(VC_KEYSCRUB_UDEV)
		// Sketch (requires -ludev): udev_monitor_new_from_netlink(udev, "udev");
		// udev_monitor_filter_add_match_subsystem_devtype(mon, "usb", NULL);
		// poll the monitor fd on a helper thread; on an "add" action call OnNewDeviceConnected().
		StartUdevDeviceMonitor ();
#elif defined(__APPLE__) && defined(VC_KEYSCRUB_IOKIT)
		// Sketch: IOServiceAddMatchingNotification(kIOFirstMatchNotification, IOUSBDevice) ->
		// OnNewDeviceConnected().
		StartIOKitDeviceMonitor ();
#else
		fprintf (stderr, "KeyScrub: new-device monitor not compiled in "
		                 "(build with VC_KEYSCRUB_UDEV / VC_KEYSCRUB_IOKIT; validate on a real session)\n");
#endif
	}

	void KeyScrubManager::Shutdown ()
	{
		pthread_mutex_lock (&Lock);
		bool joinIdle = IdleThreadStarted && !StopThreads;
		StopThreads = true;
		pthread_mutex_unlock (&Lock);

		if (joinIdle)
			pthread_join (IdleThread, 0);

		ScrubNow ("shutdown");
		VcKsRamProtectShutdown ();

		pthread_mutex_lock (&Lock);
		Enabled = false;
		IdleThreadStarted = false;
		pthread_mutex_unlock (&Lock);
	}
}

#endif /* VC_ENABLE_KEYSCRUB */
