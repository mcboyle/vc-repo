/*
 * VcJson — see VcJson.h. Bounds-checked JSON object builder with correct string escaping.
 */
#include "VcJson.h"

#if defined(VC_ENABLE_JSON)

#include <string.h>

/* append a raw byte, tracking overflow */
static void put (VcJson *j, char c)
{
	if (j->err) return;
	if (j->len + 1 >= j->cap) { j->err = 1; return; }   /* keep room for the NUL */
	j->buf[j->len++] = c;
	j->buf[j->len]   = '\0';
}

static void put_raw (VcJson *j, const char *s)
{
	while (*s) put (j, *s++);
}

/* append a JSON-escaped string (without surrounding quotes) */
static void put_escaped (VcJson *j, const char *s)
{
	static const char hex[] = "0123456789abcdef";
	const unsigned char *p = (const unsigned char *) s;
	for (; *p; p++)
	{
		unsigned char c = *p;
		switch (c)
		{
			case '"':  put (j, '\\'); put (j, '"');  break;
			case '\\': put (j, '\\'); put (j, '\\'); break;
			case '\b': put (j, '\\'); put (j, 'b');  break;
			case '\f': put (j, '\\'); put (j, 'f');  break;
			case '\n': put (j, '\\'); put (j, 'n');  break;
			case '\r': put (j, '\\'); put (j, 'r');  break;
			case '\t': put (j, '\\'); put (j, 't');  break;
			default:
				if (c < 0x20)   /* other control chars -> \u00XX */
				{
					put (j, '\\'); put (j, 'u'); put (j, '0'); put (j, '0');
					put (j, hex[(c >> 4) & 0xf]); put (j, hex[c & 0xf]);
				}
				else
					put (j, (char) c);
				break;
		}
	}
}

static void comma (VcJson *j) { if (j->n++) put (j, ','); }

void VcJsonInit (VcJson *j, char *buf, size_t cap)
{
	j->buf = buf; j->cap = cap; j->len = 0; j->err = (cap == 0); j->n = 0; j->open = 1;
	if (cap) buf[0] = '\0';
	put (j, '{');
}

void VcJsonStr (VcJson *j, const char *key, const char *value)
{
	if (!j->open) return;
	comma (j);
	put (j, '"'); put_escaped (j, key); put (j, '"'); put (j, ':');
	put (j, '"'); put_escaped (j, value ? value : ""); put (j, '"');
}

void VcJsonInt (VcJson *j, const char *key, long value)
{
	char num[32]; int i = 0, k; unsigned long v; int neg = 0;
	if (!j->open) return;
	comma (j);
	put (j, '"'); put_escaped (j, key); put (j, '"'); put (j, ':');
	if (value < 0) { neg = 1; v = (unsigned long) (-(value + 1)) + 1UL; } else v = (unsigned long) value;
	do { num[i++] = (char) ('0' + (int) (v % 10)); v /= 10; } while (v && i < (int) sizeof (num));
	if (neg) put (j, '-');
	for (k = i - 1; k >= 0; k--) put (j, num[k]);
}

void VcJsonBool (VcJson *j, const char *key, int value)
{
	if (!j->open) return;
	comma (j);
	put (j, '"'); put_escaped (j, key); put (j, '"'); put (j, ':');
	put_raw (j, value ? "true" : "false");
}

int VcJsonFinish (VcJson *j)
{
	if (!j->open) return -1;
	put (j, '}');
	j->open = 0;
	return j->err ? -1 : 0;
}

#endif /* VC_ENABLE_JSON */
