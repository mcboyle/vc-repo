/*
 * HkfOrSet — see HkfOrSet.h. Multi-token OR-set over the keyslot machinery (ROI item 45).
 *
 * Every function here is a thin, honest bridge: enrollment is one KeyslotAdd per token, opening
 * is one KeyslotOpen that the store already searches across all slots in constant time. The
 * security therefore reduces entirely to the already-proven keyslot AEAD + search — this module
 * adds no new crypto, only the OR-set framing and the HKF-response keying.
 */
#include "HkfOrSet.h"

#if defined(VC_ENABLE_HKF_ORSET) && defined(VC_ENABLE_KEYSLOTS)

#include <string.h>

int HkfOrSetEnroll (const KeyslotStoreCfg *cfg, KeyslotArea *area,
                    const unsigned char *responses, const int *respLens, int rowStride,
                    int nTokens, const unsigned char *vmk)
{
	int i;
	if (!cfg || !area || !responses || !respLens || !vmk || nTokens <= 0 || rowStride <= 0)
		return HKF_ORSET_ERR;
	for (i = 0; i < nTokens; i++) {
		int rl = respLens[i];
		if (rl <= 0 || rl > rowStride)
			return HKF_ORSET_ERR;
		/* One slot per token, all wrapping the same VMK. No duress flag on an OR-set member. */
		if (KeyslotAdd (cfg, area, responses + (size_t) i * rowStride, rl, 0, vmk) < 0)
			return HKF_ORSET_ERR;
	}
	return nTokens;
}

int HkfOrSetOpen (const KeyslotStoreCfg *cfg, KeyslotArea *area,
                  const unsigned char *response, int respLen,
                  unsigned char *vmkOut, int *flagsOut)
{
	if (!cfg || !area || !response || respLen <= 0 || !vmkOut)
		return 0;
	/* KeyslotOpen returns 1 on the first matching slot, 0 if none match — exactly the OR. */
	return KeyslotOpen (cfg, area, response, respLen, vmkOut, flagsOut);
}

int HkfOrSetEnrollConfigs (const KeyslotStoreCfg *ksCfg, KeyslotArea *area,
                           const HKFConfig *cfgs, int nTokens,
                           const unsigned char *salt, int saltLen,
                           const unsigned char *vmk)
{
	int i;
	unsigned char resp[HKF_MAX_RESPONSE];
	int rlen;
	if (!ksCfg || !area || !cfgs || nTokens <= 0 || !salt || saltLen <= 0 || !vmk)
		return HKF_ORSET_ERR;
	for (i = 0; i < nTokens; i++) {
		int rc = HKFComputeResponse (&cfgs[i], salt, saltLen, resp, &rlen);
		if (rc != HKF_OK) { memset (resp, 0, sizeof resp); return rc; }
		if (rlen <= 0 || rlen > HKF_MAX_RESPONSE) { memset (resp, 0, sizeof resp); return HKF_ORSET_ERR; }
		if (KeyslotAdd (ksCfg, area, resp, rlen, 0, vmk) < 0) { memset (resp, 0, sizeof resp); return HKF_ORSET_ERR; }
	}
	memset (resp, 0, sizeof resp);   /* do not leave a token response on the stack */
	return nTokens;
}

int HkfOrSetOpenConfig (const KeyslotStoreCfg *ksCfg, KeyslotArea *area,
                        const HKFConfig *cfg, const unsigned char *salt, int saltLen,
                        unsigned char *vmkOut, int *flagsOut)
{
	unsigned char resp[HKF_MAX_RESPONSE];
	int rlen, rc, opened;
	if (!ksCfg || !area || !cfg || !salt || saltLen <= 0 || !vmkOut)
		return 0;
	rc = HKFComputeResponse (cfg, salt, saltLen, resp, &rlen);
	if (rc != HKF_OK) { memset (resp, 0, sizeof resp); return rc; }
	if (rlen <= 0 || rlen > HKF_MAX_RESPONSE) { memset (resp, 0, sizeof resp); return 0; }
	opened = KeyslotOpen (ksCfg, area, resp, rlen, vmkOut, flagsOut);
	memset (resp, 0, sizeof resp);
	return opened;
}

#endif /* VC_ENABLE_HKF_ORSET && VC_ENABLE_KEYSLOTS */
