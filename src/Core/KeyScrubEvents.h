/*
 * KeyScrubEvents — event wiring for the cross-platform memory-key scrub (Linux/macOS application).
 *
 * The crypto core lives in Common/KeyScrub.{c,h} (secure wipe, scrub registry, RAM-encryption at
 * rest) and Common/HardwareKeyFactor.c (HKFScrubActiveConfig). This class is the C++ glue that
 * decides WHEN to scrub: it routes four events to a single ScrubNow() that erases every registered
 * secret and the active HardwareKeyFactor secret.
 *
 *   - unmount              — hooked in Core/Unix/CoreUnix.cpp::DismountVolume (fully in-process).
 *   - idle timeout         — a background monotonic-clock timer (coarse: activity is registered on
 *                            volume operations; a full build would also hook UI input).
 *   - screen lock          — Linux: logind Lock/PrepareForSleep via sd-bus (VC_KEYSCRUB_LOGIND);
 *                            macOS: com.apple.screenIsLocked. Platform glue, see the .cpp.
 *   - new-device-connect   — Linux: udev "usb" add events (VC_KEYSCRUB_UDEV); macOS: IOKit.
 *
 * The unmount and idle triggers are exercised by the verification harness and in-process logic. The
 * screen-lock and new-device monitors are OS integration that cannot be exercised in a sandbox — they
 * are compiled behind their own macros and MUST be validated on a real desktop session before being
 * relied on (see docs/MEMORY-SCRUB.md). Everything here is gated behind VC_ENABLE_KEYSCRUB; a build
 * without it is byte-for-byte stock.
 */

#ifndef TC_HEADER_Core_KeyScrubEvents
#define TC_HEADER_Core_KeyScrubEvents

#if defined(VC_ENABLE_KEYSCRUB)

#include <pthread.h>
#include <stddef.h>

namespace VeraCrypt
{
	class KeyScrubManager
	{
	public:
		static KeyScrubManager &Instance ();

		// Initialise the RAM-encryption area and start the enabled monitors. idleTimeoutSeconds <= 0
		// disables the idle-timeout trigger. Safe to call once at application start.
		void Enable (int idleTimeoutSeconds);
		bool IsEnabled () const { return Enabled; }

		// Erase every registered secret region and the active HardwareKeyFactor secret. Thread-safe;
		// safe to call when nothing is registered. 'reason' is for optional diagnostics only.
		void ScrubNow (const char *reason);

		// Reset the idle timer (call on user-driven volume operations).
		void NotifyActivity ();

		// Event entry points.
		void OnVolumeDismounted ();     // unmount trigger
		void OnScreenLocked ();         // screen-lock trigger
		void OnNewDeviceConnected ();   // new-device-connect trigger

		void Shutdown ();

	private:
		KeyScrubManager ();
		~KeyScrubManager ();
		KeyScrubManager (const KeyScrubManager &);
		KeyScrubManager &operator= (const KeyScrubManager &);

		static void  RandSeed (unsigned char *out, size_t len);   // CSPRNG seed for the RAM area
		static void *IdleThreadEntry (void *self);
		void  StartIdleMonitor ();
		void  StartScreenLockMonitor ();   // platform glue (see .cpp)
		void  StartDeviceMonitor ();       // platform glue (see .cpp)
		double MonotonicNow () const;

		bool            Enabled;
		int             IdleTimeoutSeconds;
		double          LastActivity;
		volatile bool   StopThreads;
		pthread_t       IdleThread;
		bool            IdleThreadStarted;
		mutable pthread_mutex_t Lock;
	};
}

#endif /* VC_ENABLE_KEYSCRUB */

#endif /* TC_HEADER_Core_KeyScrubEvents */
