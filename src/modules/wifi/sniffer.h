#pragma once
#include <stdint.h>

// Raw 802.11 sniffer (promiscuous mode). Aggregates frames per source device
// and streams periodic device + stats events to the WebUI / serial.
//
// channel = 0  -> lock to the current AP channel (FG_AP_CHANNEL); WebUI stays
//                 connected. This is the safe default for the WebUI button.
// channel 1..14 -> lock to that channel (WebUI clients on another channel will
//                 drop; intended for the serial path).
void fg_sniffer(uint8_t channel);
