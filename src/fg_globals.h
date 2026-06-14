#pragma once
// ============================================================
// FireGod-ESP — Global State & Shared Types
// ============================================================

#include <Arduino.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/semphr.h>
#include "config.h"

// --- Module identifiers ---
enum FGModule : uint8_t {
    MOD_NONE = 0,
    MOD_WIFI_AP_SCAN,
    MOD_WIFI_CLIENT_SCAN,
    MOD_WIFI_ARP_SCAN,
    MOD_WIFI_DEAUTH,
    MOD_WIFI_BEACON_SPAM,
    MOD_WIFI_EVIL_PORTAL,
    MOD_WIFI_KARMA,
    MOD_WIFI_SSID_CLONE,
    MOD_WIFI_SNIFFER,
    MOD_BLE_SCAN,
    MOD_BLE_SPAM,
    MOD_BLE_BAD_BLE,
};

// --- Module lifecycle ---
enum FGModuleState : uint8_t {
    STATE_IDLE = 0,
    STATE_STARTING,
    STATE_RUNNING,
    STATE_STOPPING,
};

// --- Result message sent via FreeRTOS queue ---
struct FGResultMsg {
    char json[FG_RESULT_MSG_SIZE];
};

// --- Global shared state ---
extern volatile FGModuleState g_moduleState;
extern volatile FGModule      g_activeModule;
extern volatile bool          g_stopRequested;
extern QueueHandle_t          g_resultQueue;
extern SemaphoreHandle_t      g_moduleMutex;
extern unsigned long          g_bootTime;

// --- Helper: enqueue a JSON result for WebSocket broadcast ---
void fg_send_result(const char* json);

// --- Helper: enqueue formatted result ---
void fg_send_result_fmt(const char* fmt, ...);

// --- Helper: get uptime in seconds ---
uint32_t fg_uptime_secs();

// --- Helper: MAC bytes to string ---
String fg_mac_to_str(const uint8_t* mac);

// --- Helper: encryption type to string ---
const char* fg_auth_to_str(int authmode);

// --- Helper: OUI (first 3 MAC bytes) -> vendor name, "Unknown" if absent ---
const char* fg_oui_vendor(const uint8_t* mac);
