#pragma once
// FireGod-ESP — BLE spam detector core logic (RF-independent, unit-testable).
// Pure payload classification + rotating-address sliding-window tracking.
// No NimBLE / FreeRTOS / Arduino deps so it builds natively for tests.
#include <stdint.h>
#include <string.h>

enum FGPairProto { PROTO_APPLE = 0, PROTO_SWIFTPAIR, PROTO_FASTPAIR, PROTO_N };

// Tunables (also used by the module loop for the live window readout).
#ifndef FG_WIN_MS
#define FG_WIN_MS    4000     // sliding window length (ms)
#endif
#ifndef FG_RING
#define FG_RING      96       // distinct addresses remembered per protocol
#endif
#ifndef FG_THRESH
#define FG_THRESH    12       // distinct addrs in window => flag as spam
#endif

struct ProtoState {
    uint8_t  ring[FG_RING][6];
    uint32_t ts[FG_RING];     // millis when each slot was last set (0 = empty)
    uint16_t head;
    uint32_t frames;          // total pairing frames seen (this proto)
    uint32_t lastFlag;        // millis of last emitted threat
};

// Walk length/type/value AD structures; match the byte signatures the
// proximity-pair spammers emit. Returns true and sets *proto on a match.
static inline bool fg_classify(const uint8_t* d, size_t n, FGPairProto* proto) {
    size_t i = 0;
    while (i + 1 < n) {
        uint8_t len = d[i];
        if (len == 0 || i + 1 + (size_t)len > n) break;
        uint8_t type = d[i + 1];
        const uint8_t* v = &d[i + 2];
        uint8_t vlen = len - 1;

        if (type == 0xFF && vlen >= 2) {                 // manufacturer specific
            uint16_t cid = (uint16_t)v[0] | ((uint16_t)v[1] << 8);
            if (cid == 0x004C && vlen >= 3 && v[2] == 0x07) { *proto = PROTO_APPLE;     return true; }
            if (cid == 0x0006 && vlen >= 5 && v[2] == 0x03) { *proto = PROTO_SWIFTPAIR; return true; }
        }
        // Google Fast Pair: 16-bit service data for UUID 0xFE2C.
        if (type == 0x16 && vlen >= 2 && v[0] == 0x2C && v[1] == 0xFE) { *proto = PROTO_FASTPAIR; return true; }

        i += 1 + len;
    }
    return false;
}

// Count distinct in-window addresses, inserting the current one if absent.
// Same real device re-advertising stays a single entry; a rotating spammer
// fills the ring with distinct entries fast.
static inline uint16_t fg_track_addr(ProtoState& p, const uint8_t* addr, uint32_t now) {
    int  freeSlot = -1;
    bool present  = false;
    uint16_t distinct = 0;

    for (int i = 0; i < FG_RING; i++) {
        bool live = p.ts[i] != 0 && (now - p.ts[i]) <= FG_WIN_MS;
        if (!live) { if (freeSlot < 0) freeSlot = i; p.ts[i] = 0; continue; }
        distinct++;
        if (memcmp(p.ring[i], addr, 6) == 0) { present = true; p.ts[i] = now; }
    }
    if (!present) {
        int slot = (freeSlot >= 0) ? freeSlot : p.head;
        if (freeSlot < 0) p.head = (p.head + 1) % FG_RING;   // evict oldest by ring position
        memcpy(p.ring[slot], addr, 6);
        p.ts[slot] = now;
        distinct++;
    }
    return distinct;
}
