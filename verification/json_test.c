/*
 * json_test.c — --json output correctness (ROI item 48) over the real VcJson.c + VcStatus.c.
 *
 * Emits JSON objects the way a --json CLI mode would, then json_reference.py (python's own json parser
 * = the independent oracle) checks they are valid JSON, that values round-trip, and — the point — that
 * a hostile string value (embedded quotes / backslashes / newlines / a fake `,"injected":"..."`) is
 * ESCAPED, not able to break or inject fields. VC_JSON_NEGCTL swaps in a naive unescaped builder whose
 * output the parser must reject (or show the injection), proving the escaping is load-bearing.
 */
#include <stdio.h>
#include <string.h>
#include "Common/VcJson.h"
#include "Common/VcStatus.h"

/* a value engineered to break naive JSON: a quote, a backslash, control chars, and an injection try */
static const char NASTY[] = "a\"b\\c\n\td\",\"injected\":\"pwned";

#if defined(VC_JSON_NEGCTL)
/* naive, WRONG emitter: concatenates the value with no escaping */
static void emit_label_naive (char *out, size_t cap, const char *v, int n)
{
	snprintf (out, cap, "{\"label\":\"%s\",\"n\":%d}", v, n);
}
#endif

int main (void)
{
	char buf[512];

	/* 1) a status object built from the real VcStatus taxonomy */
	{
		VcJson j; VcStatus s = VC_ERR_WRONG_PASSWORD;
		VcJsonInit (&j, buf, sizeof (buf));
		VcJsonStr  (&j, "status", VcStatusName (s));
		VcJsonInt  (&j, "code",   VcStatusExitCode (s));
		VcJsonBool (&j, "ok",     s == VC_OK);
		VcJsonStr  (&j, "detail", VcStatusString (s));
		VcJsonFinish (&j);
		printf ("%s\n", buf);
	}

	/* 2) an object whose value is the hostile string */
	{
		int n = (int) (sizeof (NASTY) - 1);
#if defined(VC_JSON_NEGCTL)
		emit_label_naive (buf, sizeof (buf), NASTY, n);
#else
		VcJson j;
		VcJsonInit (&j, buf, sizeof (buf));
		VcJsonStr  (&j, "label", NASTY);
		VcJsonInt  (&j, "n",     n);
		VcJsonFinish (&j);
#endif
		printf ("%s\n", buf);
	}

	return 0;
}
