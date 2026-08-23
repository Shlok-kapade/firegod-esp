#pragma once
// FireGod-ESP — SSID clone: beacons a single target SSID (evil-twin bait).
// ssid: SSID to clone (required). channel: 0 => AP channel, else fixed.
// privacy: advertise WPA2 (true) vs open (false).
#include <Arduino.h>
void fg_ssid_clone(const char* ssid, uint8_t channel, bool privacy);
