#pragma once
// ============================================================
// FireGod-ESP — 802.11 frame builders (shared by offensive modules)
// Callback/loop-safe: no heap, caller-supplied buffers.
// ============================================================

#include <Arduino.h>

// Fill a 6-byte locally-administered random unicast MAC into `mac`.
void fg_rand_mac(uint8_t* mac);

// Build a beacon frame for `ssid` advertised by BSSID `src` on `channel`.
// Writes into `buf` (must be >= 128 bytes) and returns the frame length.
// `privacy` adds the WPA2 capability/RSN hint so it looks encrypted.
int  fg_build_beacon(uint8_t* buf, const char* ssid, const uint8_t* src,
                     uint8_t channel, bool privacy);

// Build a deauth (reason 0x07) from `bssid` to `dst` (broadcast for all STAs).
// Writes 26 bytes into `buf`; returns length. `disassoc` sends subtype 0x0A.
int  fg_build_deauth(uint8_t* buf, const uint8_t* bssid, const uint8_t* dst,
                     bool disassoc);

// Build a probe-response for `ssid` from `src` to `dst` on `channel` (karma).
int  fg_build_probe_resp(uint8_t* buf, const char* ssid, const uint8_t* src,
                         const uint8_t* dst, uint8_t channel);
