#pragma once
// FireGod-ESP — Deauth: floods deauth/disassoc frames at a target BSSID.
// bssidStr: "AA:BB:CC:DD:EE:FF". channel: AP's channel (1-14, required).
// targetStr: optional client MAC; empty/null => broadcast (all clients).
#include <Arduino.h>
void fg_deauth(const char* bssidStr, const char* targetStr, uint8_t channel);
