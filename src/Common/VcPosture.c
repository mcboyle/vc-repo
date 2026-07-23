/*
 * VcPosture — see VcPosture.h. Security-posture report derived from the real compile guards.
 */
#include "VcPosture.h"

#if defined(VC_ENABLE_POSTURE) && defined(VC_ENABLE_JSON)

#include "VcJson.h"

/* Map each feature's compile guard to a 0/1 constant, so the report tracks the actual build.
 * When VP_NEGCTL is defined (test-only), every feature reports 1 regardless — the negative
 * control that must be caught by a build that has the feature OFF. */
#if defined(VP_NEGCTL)
#  define VP(flag) 1
#else
#  define VP(flag) (defined_##flag)
#endif

/* helper: 1 if the macro is defined, else 0 */
#if defined(VC_ENABLE_KEYSLOTS)
#  define defined_KEYSLOTS 1
#else
#  define defined_KEYSLOTS 0
#endif
#if defined(VC_ENABLE_DURESS)
#  define defined_DURESS 1
#else
#  define defined_DURESS 0
#endif
#if defined(VC_ENABLE_KEYSCRUB)
#  define defined_KEYSCRUB 1
#else
#  define defined_KEYSCRUB 0
#endif
#if defined(VC_ENABLE_HKF)
#  define defined_HKF 1
#else
#  define defined_HKF 0
#endif
#if defined(VC_ENABLE_HKF_ORSET)
#  define defined_HKF_ORSET 1
#else
#  define defined_HKF_ORSET 0
#endif
#if defined(VC_ENABLE_ARGON2_PARAMS)
#  define defined_ARGON2_PARAMS 1
#else
#  define defined_ARGON2_PARAMS 0
#endif
#if defined(VC_ENABLE_HEADER_BACKUP)
#  define defined_HEADER_BACKUP 1
#else
#  define defined_HEADER_BACKUP 0
#endif
#if defined(VC_ENABLE_SELFTEST)
#  define defined_SELFTEST 1
#else
#  define defined_SELFTEST 0
#endif

struct posture_field { const char *key; int on; };

static void posture_fields (struct posture_field *f, int *nOut)
{
	int n = 0;
	f[n].key = "keyslots";       f[n].on = VP(KEYSLOTS);       n++;
	f[n].key = "duress";         f[n].on = VP(DURESS);         n++;
	f[n].key = "keyscrub";       f[n].on = VP(KEYSCRUB);       n++;
	f[n].key = "hardware_factor";f[n].on = VP(HKF);            n++;
	f[n].key = "multi_token_or"; f[n].on = VP(HKF_ORSET);      n++;
	f[n].key = "argon2_params";  f[n].on = VP(ARGON2_PARAMS);  n++;
	f[n].key = "header_backup";  f[n].on = VP(HEADER_BACKUP);  n++;
	f[n].key = "self_test";      f[n].on = VP(SELFTEST);       n++;
	*nOut = n;
}

int VcPostureFeatureCount (void)
{
	struct posture_field f[16]; int n, i, c = 0;
	posture_fields (f, &n);
	for (i = 0; i < n; i++) if (f[i].on) c++;
	return c;
}

int VcPostureReportJson (char *buf, size_t cap)
{
	VcJson j; struct posture_field f[16]; int n, i, c = 0;
	posture_fields (f, &n);
	for (i = 0; i < n; i++) if (f[i].on) c++;
	VcJsonInit (&j, buf, cap);
	VcJsonStr  (&j, "report", "security-posture");
	for (i = 0; i < n; i++) VcJsonBool (&j, f[i].key, f[i].on);
	VcJsonInt  (&j, "features_on", c);
	VcJsonBool (&j, "hardened", c > 0);
	return VcJsonFinish (&j);
}

#endif /* VC_ENABLE_POSTURE && VC_ENABLE_JSON */
