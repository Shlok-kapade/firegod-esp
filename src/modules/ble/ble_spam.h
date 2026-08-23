#pragma once
// FireGod-ESP — BLE advertisement spam.
// Cycles fake pairing adverts (Apple proximity / Microsoft SwiftPair /
// Android Fast Pair) with a fresh random MAC each burst, triggering
// device-nearby / pairing popups on phones in range. Authorized testing only.
// mode: 0 = cycle all, 1 = Apple, 2 = Microsoft, 3 = Android.
#include <Arduino.h>
void fg_ble_spam(uint8_t mode);
