/*
 * VcPosture — one-command security-posture report (ROI-TOP-50 item 18).
 *
 * Answers "what protections does THIS build/volume actually have on?" in one machine-readable
 * blob, so a user (or a script) never has to guess whether the hardening they think they enabled
 * is compiled in. The report is a JSON object (built with the item-48 VcJson escaper) whose boolean
 * fields reflect the VC_ENABLE_* features compiled into this binary, plus a summary count. It is
 * derived from the real compile guards — not a hand-maintained list that can drift — so a feature
 * that is off genuinely reports false.
 *
 * Gated behind VC_ENABLE_POSTURE (needs VC_ENABLE_JSON for the builder); default build stays stock.
 */
#ifndef TC_HEADER_Common_VcPosture
#define TC_HEADER_Common_VcPosture

#include "Tcdefs.h"

#if defined(VC_ENABLE_POSTURE) && defined(VC_ENABLE_JSON)

#include <stddef.h>

#if defined(__cplusplus)
extern "C" {
#endif

/* Emit the security-posture report as a JSON object into (buf, cap). Returns 0 on success or -1 if
 * the buffer overflowed (VcJson fail-closed). The fields reflect this binary's compiled-in features. */
int VcPostureReportJson (char *buf, size_t cap);

/* Number of hardening features currently compiled in (the "features_on" count in the report). */
int VcPostureFeatureCount (void);

#if defined(__cplusplus)
}
#endif

#endif /* VC_ENABLE_POSTURE && VC_ENABLE_JSON */

#endif /* TC_HEADER_Common_VcPosture */
