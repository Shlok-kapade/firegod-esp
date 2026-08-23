// ============================================================
// FireGod-ESP — BLE Pairing-Spam Detector (defensive)
//
// Passive scan that classifies each advert into a proximity-pairing
// protocol and detects the spam signature we (and Bruce/Marauder/Flipper)
// generate: a burst of pairing frames from MANY distinct random-static
// addresses in a few seconds. A real environment has a handful of stable
// nearby devices; a spammer churns a fresh MAC every cycle, so "unique
// rotating addresses per protocol per window" is the discriminator.
//
// Detection is by AD payload structure, not by MAC — MACs are spoofed.
// Runs beside the WiFi SoftAP via coexistence. Authorized monitoring only.
// ============================================================

#include "ble_detect.h"
#include "ble_detect_core.h"     // pure classify + window logic (shared with native tests)
#include "fg_globals.h"
#include <NimBLEDevice.h>

static const char* PROTO_NAME[PROTO_N] = {"apple_continuity", "ms_swiftpair", "google_fastpair"};

#define FG_REFLAG_MS     5000     // min gap between repeat threat alerts (per proto)

static ProtoState   s_proto[PROTO_N];
static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;
static volatile uint32_t s_advTotal = 0;

static void reset_state() {
    memset(s_proto, 0, sizeof(s_proto));
    s_advTotal = 0;
}

class FGDetectCB : public NimBLEScanCallbacks {
    void onResult(const NimBLEAdvertisedDevice* dev) override {
        const std::vector<uint8_t>& pl = dev->getPayload();
        if (pl.empty()) return;

        FGPairProto proto;
        if (!fg_classify(pl.data(), pl.size(), &proto)) { s_advTotal++; return; }

        uint8_t addr[6];
        memcpy(addr, dev->getAddress().getBase()->val, 6);   // NimBLE stores LSB-first; fine as an identity key
        bool randomStatic = (addr[5] & 0xC0) == 0xC0;        // spammers use static-random MACs
        uint32_t now = millis();

        uint16_t distinct;
        bool flag = false;
        portENTER_CRITICAL(&s_mux);
        s_advTotal++;
        ProtoState& p = s_proto[proto];
        p.frames++;
        distinct = fg_track_addr(p, addr, now);
        if (distinct >= FG_THRESH && (p.lastFlag == 0 || now - p.lastFlag >= FG_REFLAG_MS)) {
            p.lastFlag = now;
            flag = true;
        }
        uint32_t frames = p.frames;
        portEXIT_CRITICAL(&s_mux);

        if (flag) {
            fg_send_result_fmt(
                "{\"event\":\"ble_threat\",\"proto\":\"%s\",\"distinct_macs\":%u,"
                "\"window_ms\":%u,\"frames\":%lu,\"rotating\":%s,"
                "\"severity\":\"%s\"}",
                PROTO_NAME[proto], (unsigned)distinct, (unsigned)FG_WIN_MS,
                (unsigned long)frames, randomStatic ? "true" : "false",
                distinct >= FG_THRESH * 2 ? "high" : "medium");
            Serial.printf("[BLE] THREAT %s: %u rotating MACs / %ums\n",
                          PROTO_NAME[proto], (unsigned)distinct, (unsigned)FG_WIN_MS);
        }
    }
};

static FGDetectCB s_cb;

void fg_ble_detect(uint32_t durationSecs) {
    reset_state();

    fg_send_result_fmt("{\"event\":\"log\",\"msg\":\"BLE spam detector starting%s...\"}",
                       durationSecs ? "" : " (until stop)");
    Serial.println("[BLE] Detector starting");

    NimBLEDevice::init("");
    NimBLEDevice::setOwnAddrType(BLE_OWN_ADDR_PUBLIC);   // in case a prior spam left RANDOM
    NimBLEScan* scan = NimBLEDevice::getScan();
    scan->setScanCallbacks(&s_cb, false);
    scan->setActiveScan(false);     // passive: we only read adverts, never probe
    scan->setInterval(80);
    scan->setWindow(80);            // ~100% duty so we don't miss short bursts
    scan->setMaxResults(0);         // callback-only
    scan->start(0, false);

    uint32_t started = millis(), lastEmit = started;
    while (!g_stopRequested) {
        vTaskDelay(pdMS_TO_TICKS(50));
        uint32_t now = millis();
        if (now - lastEmit >= 1000) {
            lastEmit = now;
            uint32_t live[PROTO_N];
            portENTER_CRITICAL(&s_mux);
            for (int k = 0; k < PROTO_N; k++) {
                uint16_t d = 0;
                for (int i = 0; i < FG_RING; i++)
                    if (s_proto[k].ts[i] && (now - s_proto[k].ts[i]) <= FG_WIN_MS) d++;
                live[k] = d;
            }
            uint32_t total = s_advTotal;
            portEXIT_CRITICAL(&s_mux);
            fg_send_result_fmt(
                "{\"event\":\"ble_detect_stats\",\"adverts\":%lu,"
                "\"apple\":%lu,\"swiftpair\":%lu,\"fastpair\":%lu,\"secs\":%lu}",
                (unsigned long)total, (unsigned long)live[PROTO_APPLE],
                (unsigned long)live[PROTO_SWIFTPAIR], (unsigned long)live[PROTO_FASTPAIR],
                (unsigned long)((now - started) / 1000));
        }
        if (durationSecs && (now - started) >= durationSecs * 1000UL) break;
    }

    scan->stop();
    NimBLEDevice::deinit(true);

    fg_send_result_fmt("{\"event\":\"scan_complete\",\"type\":\"ble_detect\",\"count\":%lu}",
                       (unsigned long)s_advTotal);
    Serial.printf("[BLE] Detector stopped. %lu adverts.\n", (unsigned long)s_advTotal);
}
