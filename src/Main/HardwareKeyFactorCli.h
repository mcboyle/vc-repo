/*
 * HardwareKeyFactorCli — turns command-line option strings into a validated HKFConfig, and is the
 * piece the wxWidgets option glue in Main/CommandLineInterface.cpp calls. It is deliberately free of
 * any wx dependency so it can be unit-tested on its own (see verification/hkf_cli_test.cpp).
 *
 * Suggested CLI options (registered in CommandLineInterface.cpp):
 *   --hkf-backend <none|yubikey|fido2|simulator>
 *   --hkf-yk-slot <1|2>                     (yubikey; default 2)
 *   --hkf-fido-rp <relying-party-id>        (fido2)
 *   --hkf-fido-credid <hex>                 (fido2; credential id from enrollment)
 *   --hkf-fido-pin <pin>                    (fido2; optional)
 *   --hkf-sim-secret <hex> --hkf-sim-mac <1|2>   (simulator; testing only)
 */

#ifndef TC_HEADER_Main_HardwareKeyFactorCli
#define TC_HEADER_Main_HardwareKeyFactorCli

#include <string>
#include <cstring>

extern "C" {
#include "Common/HardwareKeyFactor.h"
}

namespace VeraCrypt
{
	inline bool HKFHexToBytes (const std::string &hex, unsigned char *out, int maxLen, int &outLen, std::string &error)
	{
		if (hex.size() % 2 != 0) { error = "hex value must have an even number of digits"; return false; }
		int n = (int)(hex.size() / 2);
		if (n > maxLen) { error = "hex value is too long"; return false; }
		for (int i = 0; i < n; i++)
		{
			int hi = -1, lo = -1;
			char ch = hex[2*i], cl = hex[2*i+1];
			if      (ch >= '0' && ch <= '9') hi = ch - '0';
			else if (ch >= 'a' && ch <= 'f') hi = ch - 'a' + 10;
			else if (ch >= 'A' && ch <= 'F') hi = ch - 'A' + 10;
			if      (cl >= '0' && cl <= '9') lo = cl - '0';
			else if (cl >= 'a' && cl <= 'f') lo = cl - 'a' + 10;
			else if (cl >= 'A' && cl <= 'F') lo = cl - 'A' + 10;
			if (hi < 0 || lo < 0) { error = "invalid hex digit"; return false; }
			out[i] = (unsigned char)((hi << 4) | lo);
		}
		outLen = n;
		return true;
	}

	/* Fill cfg from parsed option strings. Returns false and sets 'error' on invalid input.
	   An empty / "none" backend yields HKF_BACKEND_NONE (feature off). */
	inline bool BuildHKFConfig (const std::string &backend, int ykSlot,
	                            const std::string &fidoRp, const std::string &fidoCredIdHex, const std::string &fidoPin,
	                            const std::string &simSecretHex, int simMac,
	                            HKFConfig &cfg, std::string &error)
	{
		memset (&cfg, 0, sizeof cfg);

		if (backend.empty() || backend == "none")
		{
			cfg.backend = HKF_BACKEND_NONE;
			return true;
		}
		if (backend == "yubikey" || backend == "yk")
		{
			cfg.backend = HKF_BACKEND_YK_HMAC_SHA1;
			if (ykSlot != 1 && ykSlot != 2) { error = "--hkf-yk-slot must be 1 or 2"; return false; }
			cfg.ykSlot = ykSlot;
			cfg.ykMayBlock = 1;
			return true;
		}
		if (backend == "fido2")
		{
			cfg.backend = HKF_BACKEND_FIDO2_HMAC_SECRET;
			if (fidoRp.empty()) { error = "--hkf-fido-rp is required for fido2"; return false; }
			if (fidoRp.size() >= sizeof (cfg.fidoRpId)) { error = "--hkf-fido-rp is too long"; return false; }
			strncpy (cfg.fidoRpId, fidoRp.c_str(), sizeof (cfg.fidoRpId) - 1);
			if (fidoCredIdHex.empty()) { error = "--hkf-fido-credid is required for fido2"; return false; }
			if (!HKFHexToBytes (fidoCredIdHex, cfg.fidoCredId, HKF_MAX_CRED_ID, cfg.fidoCredIdLen, error)) return false;
			if (fidoPin.size() >= sizeof (cfg.fidoPin)) { error = "--hkf-fido-pin is too long"; return false; }
			if (!fidoPin.empty()) strncpy (cfg.fidoPin, fidoPin.c_str(), sizeof (cfg.fidoPin) - 1);
			return true;
		}
		if (backend == "simulator" || backend == "sim")
		{
			cfg.backend = HKF_BACKEND_SIMULATOR;
			if (simMac != 1 && simMac != 2) { error = "--hkf-sim-mac must be 1 or 2"; return false; }
			cfg.simMac = simMac;
			if (!HKFHexToBytes (simSecretHex, cfg.simSecret, (int) sizeof (cfg.simSecret), cfg.simSecretLen, error)) return false;
			if (cfg.simSecretLen < 1) { error = "--hkf-sim-secret is required for simulator"; return false; }
			return true;
		}
		error = "unknown --hkf-backend '" + backend + "' (expected none|yubikey|fido2|simulator)";
		return false;
	}
}

#endif /* TC_HEADER_Main_HardwareKeyFactorCli */
