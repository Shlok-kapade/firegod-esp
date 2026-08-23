#pragma once
// FireGod-ESP — Beacon spam: floods fake AP beacons.
// ssidArg: optional comma-separated SSID list; empty => built-in list.
// channel: 0 => hop 1/6/11, else fixed channel.
#include <Arduino.h>
void fg_beacon_spam(const char* ssidArg, uint8_t channel);
