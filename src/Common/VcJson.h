/*
 * VcJson — a tiny, bounds-checked JSON object builder for --json output (ROI-TOP-50 item 48).
 *
 * Scripts want machine-readable results, not scraped English. The correctness-critical part is string
 * escaping: a volume label, path, or error detail can contain '"', '\', or control characters that
 * would otherwise break the JSON or inject fields. VcJson escapes every string value so the output is
 * always valid JSON. Keys are caller-supplied literals (assumed safe). Fixed caller buffer, no
 * allocation; overflow is reported, never overrun. Gated behind VC_ENABLE_JSON.
 */
#ifndef TC_HEADER_Common_VcJson
#define TC_HEADER_Common_VcJson

#include "Tcdefs.h"

#if defined(VC_ENABLE_JSON)

#include <stddef.h>

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct
{
	char  *buf;
	size_t cap;
	size_t len;
	int    err;       /* set once the buffer overflows; all further writes are no-ops */
	int    n;         /* number of fields emitted (controls comma placement) */
	int    open;      /* 1 between VcJsonInit and VcJsonFinish */
} VcJson;

/* Begin a JSON object in the caller's buffer. */
void VcJsonInit  (VcJson *j, char *buf, size_t cap);
/* Add "key":"value" — value is JSON-escaped. */
void VcJsonStr   (VcJson *j, const char *key, const char *value);
/* Add "key":<int>. */
void VcJsonInt   (VcJson *j, const char *key, long value);
/* Add "key":true|false. */
void VcJsonBool  (VcJson *j, const char *key, int value);
/* Close the object. Returns 0 on success, -1 if the output was truncated (buffer too small). */
int  VcJsonFinish(VcJson *j);

#if defined(__cplusplus)
}
#endif

#endif /* VC_ENABLE_JSON */

#endif /* TC_HEADER_Common_VcJson */
