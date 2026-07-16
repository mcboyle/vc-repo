#include "Common/HardwareKeyFactor.h"
/* mirror the real KEY_INFO field types (Crypto.h): userKey unsigned __int8[128], keyLength int, salt unsigned __int8[64] */
struct kinfo { unsigned __int8 userKey[128]; int keyLength; unsigned __int8 salt[64]; };
int test_mount(struct kinfo* keyInfo){
  return HKFApplyIfConfigured (keyInfo->userKey, &keyInfo->keyLength, keyInfo->salt, 64) != HKF_OK;
}
int test_format(struct kinfo keyInfo, void* password){
  return (password && HKFApplyIfConfigured (keyInfo.userKey, &keyInfo.keyLength, keyInfo.salt, 64) != HKF_OK);
}
