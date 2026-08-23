// Native unit test for the BLE spam detector core (RF-independent).
// Build & run:  g++ -std=c++17 -I src test/test_ble_detect.cpp -o /tmp/t && /tmp/t
#include "modules/ble/ble_detect_core.h"
#include <cstdio>
#include <vector>
#include <cassert>

static int failures = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("  FAIL: %s\n", msg); failures++; } \
    else         { printf("  ok:   %s\n", msg); } } while (0)

// Build the exact adverts our spammer emits (mirrors ble_spam.cpp builders).
static std::vector<uint8_t> apple() {
    return {0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x0e,0x20,0x55, /*+random*/ 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21};
}
static std::vector<uint8_t> swiftpair() {
    return {0x02,0x01,0x06, 0x09,0xff,0x06,0x00,0x03,0x00,0x80,'A','B','C'};
}
static std::vector<uint8_t> fastpair() {
    return {0x02,0x01,0x06, 0x03,0x03,0x2c,0xfe, 0x06,0x16,0x2c,0xfe,0x00,0x01,0xf0, 0x02,0x0a,0x14};
}
// Benign devices that must NOT classify.
static std::vector<uint8_t> heartrate() {                 // 0x180D service + name
    return {0x02,0x01,0x06, 0x03,0x03,0x0d,0x18, 0x06,0x09,'B','a','n','d'};
}
static std::vector<uint8_t> ibeacon() {                    // Apple mfr but iBeacon (0x02), not pairing (0x07)
    return {0x1a,0xff,0x4c,0x00,0x02,0x15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,0,0,0,0xc5};
}

static void mac(uint8_t* a, uint8_t seed) {
    for (int i=0;i<6;i++) a[i] = seed + i*7;
    a[5] |= 0xC0;   // static-random, like the spammer
}

int main() {
    printf("== classifier ==\n");
    FGPairProto p;
    auto a=apple(); CHECK(fg_classify(a.data(),a.size(),&p) && p==PROTO_APPLE,     "apple continuity -> APPLE");
    auto s=swiftpair(); CHECK(fg_classify(s.data(),s.size(),&p) && p==PROTO_SWIFTPAIR,"swiftpair -> SWIFTPAIR");
    auto f=fastpair(); CHECK(fg_classify(f.data(),f.size(),&p) && p==PROTO_FASTPAIR, "fastpair -> FASTPAIR");
    auto h=heartrate(); CHECK(!fg_classify(h.data(),h.size(),&p),                   "heart-rate band -> not pairing");
    auto b=ibeacon(); CHECK(!fg_classify(b.data(),b.size(),&p),                     "iBeacon -> not pairing (type 0x02)");
    std::vector<uint8_t> junk={0x02,0x01,0x06}; CHECK(!fg_classify(junk.data(),junk.size(),&p), "flags-only -> not pairing");
    // truncated/malformed length must not over-read or match
    std::vector<uint8_t> bad={0x1e,0xff,0x4c,0x00,0x07}; CHECK(!fg_classify(bad.data(),bad.size(),&p), "truncated apple -> no match, no overread");

    printf("== window: spammer (rotating MACs) trips threshold ==\n");
    ProtoState st{}; uint8_t m[6]; uint16_t d=0;
    for (int i=0;i<FG_THRESH;i++){ mac(m,(uint8_t)(i*3+1)); d=fg_track_addr(st,m,1000+i*40); }
    CHECK(d>=FG_THRESH, "FG_THRESH distinct rotating MACs -> distinct>=threshold");

    printf("== window: one real device re-advertising does NOT inflate ==\n");
    ProtoState st2{}; uint8_t fixed[6]; mac(fixed,99); uint16_t d2=0;
    for (int i=0;i<50;i++) d2=fg_track_addr(st2,fixed,2000+i*100);   // same MAC, 50 adverts
    CHECK(d2==1, "same MAC x50 -> distinct stays 1 (no false positive)");

    printf("== window: stale entries age out past FG_WIN_MS ==\n");
    ProtoState st3{}; uint8_t m3[6];
    mac(m3,5);  fg_track_addr(st3,m3,1000);
    mac(m3,55); uint16_t d3=fg_track_addr(st3,m3,1000+FG_WIN_MS+500);  // first is now stale
    CHECK(d3==1, "address older than window is dropped from distinct count");

    printf("\n%s (%d failure%s)\n", failures? "TESTS FAILED":"ALL TESTS PASSED", failures, failures==1?"":"s");
    return failures ? 1 : 0;
}
