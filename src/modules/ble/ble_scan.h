#pragma once
// FireGod-ESP — BLE scanner (NimBLE active scan).
// durationSecs: 0 => scan until 'stop'; otherwise stop after N seconds.
// Streams {"event":"ble_dev",...} per device + periodic {"event":"ble_stats",...}.
#include <Arduino.h>
void fg_ble_scan(uint32_t durationSecs);
