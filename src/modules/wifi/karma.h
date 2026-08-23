#pragma once
// FireGod-ESP — Karma: answers client probe requests with matching
// probe-responses + beacons so devices think their saved networks are
// present. channel: 0 => AP channel, else fixed. Authorized testing only.
#include <Arduino.h>
void fg_karma(uint8_t channel);
