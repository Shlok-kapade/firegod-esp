#pragma once
// FireGod-ESP — BLE pairing-spam detector (defensive).
// Passive NimBLE scan that classifies advertising payloads into known
// proximity-pairing protocols (Apple Continuity, Microsoft SwiftPair,
// Google Fast Pair) and flags the spam signature: a flood of pairing frames
// arriving from many rapidly-rotating random-static addresses in a short
// window — which a handful of real nearby devices never produce.
// durationSecs: 0 => run until 'stop'; otherwise stop after N seconds.
// Streams {"event":"ble_threat",...} when a protocol crosses threshold,
// plus periodic {"event":"ble_detect_stats",...}.
#include <Arduino.h>
void fg_ble_detect(uint32_t durationSecs);
