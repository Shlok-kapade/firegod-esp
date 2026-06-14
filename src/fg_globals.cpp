// ============================================================
// FireGod-ESP — Global State Implementation
// ============================================================

#include "fg_globals.h"
#include <stdarg.h>
#include <esp_wifi_types.h>   // WIFI_AUTH_* enum for fg_auth_to_str

volatile FGModuleState g_moduleState = STATE_IDLE;
volatile FGModule      g_activeModule = MOD_NONE;
volatile bool          g_stopRequested = false;
QueueHandle_t          g_resultQueue = nullptr;
SemaphoreHandle_t      g_moduleMutex = nullptr;
unsigned long          g_bootTime = 0;

void fg_send_result(const char* json) {
    if (!g_resultQueue) return;
    FGResultMsg msg;
    strncpy(msg.json, json, FG_RESULT_MSG_SIZE - 1);
    msg.json[FG_RESULT_MSG_SIZE - 1] = '\0';
    // Non-blocking send — drop if queue full (better than blocking a scan)
    xQueueSend(g_resultQueue, &msg, 0);
}

void fg_send_result_fmt(const char* fmt, ...) {
    char buf[FG_RESULT_MSG_SIZE];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    fg_send_result(buf);
}

uint32_t fg_uptime_secs() {
    return (millis() - g_bootTime) / 1000;
}

String fg_mac_to_str(const uint8_t* mac) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return String(buf);
}

// --- OUI vendor lookup (top manufacturers, stored in flash) ---
struct FGOuiEntry {
    uint8_t prefix[3];
    const char* vendor;
};

static const FGOuiEntry PROGMEM g_oui_table[] = {
    {{0x00, 0x1A, 0x2B}, "Ayecom"},
    {{0x3C, 0x5A, 0xB4}, "Google"},
    {{0xAC, 0x84, 0xC6}, "TP-Link"},
    {{0xD8, 0x0D, 0x17}, "TP-Link"},
    {{0x50, 0xC7, 0xBF}, "TP-Link"},
    {{0x14, 0xCC, 0x20}, "TP-Link"},
    {{0xB0, 0xBE, 0x76}, "TP-Link"},
    {{0x00, 0x1E, 0x58}, "D-Link"},
    {{0x28, 0xEE, 0x52}, "D-Link"},
    {{0xFC, 0x15, 0xB4}, "Huawei"},
    {{0x48, 0x46, 0xFB}, "Huawei"},
    {{0x00, 0x25, 0x9C}, "Cisco"},
    {{0xF8, 0xBB, 0xBF}, "Cisco"},
    {{0xDC, 0xA6, 0x32}, "Raspberry"},
    {{0xB8, 0x27, 0xEB}, "Raspberry"},
    {{0x24, 0x6F, 0x28}, "Espressif"},
    {{0xAC, 0x67, 0xB2}, "Espressif"},
    {{0x30, 0xAE, 0xA4}, "Espressif"},
    {{0xA4, 0xCF, 0x12}, "Espressif"},
    {{0x78, 0x21, 0x84}, "Samsung"},
    {{0xE4, 0x58, 0xE7}, "Samsung"},
    {{0x34, 0x14, 0xB5}, "Samsung"},
    {{0x3C, 0x22, 0xFB}, "Apple"},
    {{0xA4, 0x83, 0xE7}, "Apple"},
    {{0xF0, 0x18, 0x98}, "Apple"},
    {{0x60, 0x6C, 0x66}, "Intel"},
    {{0x8C, 0x16, 0x45}, "Intel"},
    {{0xA0, 0x36, 0x9F}, "Intel"},
    {{0x00, 0x50, 0xF2}, "Microsoft"},
    {{0x7C, 0x5C, 0xF8}, "Qualcomm"},
    {{0x9C, 0xB6, 0xD0}, "Rivet/Killer"},
    {{0x44, 0x03, 0x2C}, "Xiaomi"},
    {{0x64, 0xCC, 0x2E}, "Xiaomi"},
    {{0x20, 0x34, 0xFB}, "Xiaomi"},
    {{0xFC, 0xAA, 0x14}, "Gree"},
    {{0x68, 0xDB, 0xF5}, "Amazon"},
    {{0xF0, 0x72, 0xEA}, "Amazon"},
    {{0x40, 0xB4, 0xCD}, "Amazon"},
};
static const int FG_OUI_COUNT = sizeof(g_oui_table) / sizeof(g_oui_table[0]);

const char* fg_oui_vendor(const uint8_t* mac) {
    for (int i = 0; i < FG_OUI_COUNT; i++) {
        if (mac[0] == g_oui_table[i].prefix[0] &&
            mac[1] == g_oui_table[i].prefix[1] &&
            mac[2] == g_oui_table[i].prefix[2]) {
            return g_oui_table[i].vendor;
        }
    }
    return "Unknown";
}

const char* fg_auth_to_str(int authmode) {
    switch (authmode) {
        case WIFI_AUTH_OPEN:            return "OPEN";
        case WIFI_AUTH_WEP:             return "WEP";
        case WIFI_AUTH_WPA_PSK:         return "WPA";
        case WIFI_AUTH_WPA2_PSK:        return "WPA2";
        case WIFI_AUTH_WPA_WPA2_PSK:    return "WPA/WPA2";
        case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2-ENT";
        case WIFI_AUTH_WPA3_PSK:        return "WPA3";
        case WIFI_AUTH_WPA2_WPA3_PSK:   return "WPA2/WPA3";
        default:                        return "UNKNOWN";
    }
}
