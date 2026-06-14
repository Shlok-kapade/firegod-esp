// ============================================================
// FireGod-ESP — Web Server + WebSocket Implementation
// ============================================================

#include "web_server.h"
#include "fg_globals.h"
#include "core/wifi_manager.h"
#include "modules/wifi/ap_scanner.h"
#include "modules/wifi/client_scanner.h"
#include "modules/wifi/arp_scanner.h"
#include "modules/wifi/sniffer.h"
#include <ArduinoJson.h>
#include <ESPAsyncWebServer.h>

// --- Web assets from PROGMEM ---
#include "data/web_assets.h"

static AsyncWebServer  server(FG_WEB_PORT);
static AsyncWebSocket  ws(FG_WS_PATH);

// Forward declarations for module launch
static void module_task_wrapper(void* param);

// --- Module launch params (passed to task) ---
struct ModuleLaunchParams {
    FGModule mod;
    char ssid[33];
    char pass[65];
    uint8_t channel;
};

// ============================================================
// WebSocket event handler
// ============================================================
static void onWsEvent(AsyncWebSocket* server, AsyncWebSocketClient* client,
                       AwsEventType type, void* arg, uint8_t* data, size_t len) {
    if (type == WS_EVT_CONNECT) {
        Serial.printf("[WS] Client #%u connected\n", client->id());
        // Send welcome status
        fg_send_result_fmt("{\"event\":\"status\",\"module\":\"%s\",\"state\":\"%s\",\"heap\":%lu,\"uptime\":%lu,\"version\":\"%s\"}",
            g_activeModule == MOD_NONE ? "none" : "active",
            g_moduleState == STATE_IDLE ? "idle" : "busy",
            (unsigned long)ESP.getFreeHeap(),
            (unsigned long)fg_uptime_secs(),
            FG_VERSION);
    }
    else if (type == WS_EVT_DISCONNECT) {
        Serial.printf("[WS] Client #%u disconnected\n", client->id());
    }
    else if (type == WS_EVT_DATA) {
        AwsFrameInfo* info = (AwsFrameInfo*)arg;
        if (info->final && info->index == 0 && info->len == len && info->opcode == WS_TEXT) {
            // Parse JSON straight from the bounded frame buffer — do NOT write
            // a terminator at data[len] (that's one byte past the buffer).
            JsonDocument doc;
            DeserializationError err = deserializeJson(doc, (const char*)data, len);
            Serial.printf("[WS] Received %u bytes\n", (unsigned)len);
            if (err) {
                fg_send_result("{\"event\":\"error\",\"msg\":\"Invalid JSON\"}");
                return;
            }

            const char* cmd = doc["cmd"];
            if (!cmd) {
                fg_send_result("{\"event\":\"error\",\"msg\":\"Missing cmd field\"}");
                return;
            }

            // --- Command dispatch ---
            if (strcmp(cmd, "wifi_scan") == 0) {
                fg_launch_module(MOD_WIFI_AP_SCAN);
            }
            else if (strcmp(cmd, "client_scan") == 0) {
                const char* ssid = doc["ssid"];
                const char* pass = doc["pass"];
                if (!ssid || !pass) {
                    fg_send_result("{\"event\":\"error\",\"msg\":\"client_scan requires ssid and pass\"}");
                    return;
                }
                fg_launch_module(MOD_WIFI_CLIENT_SCAN, ssid, pass);
            }
            else if (strcmp(cmd, "arp_scan") == 0) {
                const char* ssid = doc["ssid"];
                const char* pass = doc["pass"];
                if (!ssid || !pass) {
                    fg_send_result("{\"event\":\"error\",\"msg\":\"arp_scan requires ssid and pass\"}");
                    return;
                }
                fg_launch_module(MOD_WIFI_ARP_SCAN, ssid, pass);
            }
            else if (strcmp(cmd, "sniff") == 0) {
                // Optional "channel": 0 (default) locks to AP channel so the
                // WebUI stays connected; 1..14 pins an arbitrary channel.
                int ch = doc["channel"] | 0;
                if (ch < 0 || ch > 14) ch = 0;
                fg_launch_module(MOD_WIFI_SNIFFER, nullptr, nullptr, (uint8_t)ch);
            }
            else if (strcmp(cmd, "stop") == 0) {
                g_stopRequested = true;
                fg_send_result("{\"event\":\"log\",\"msg\":\"Stop requested...\"}");
            }
            else if (strcmp(cmd, "status") == 0) {
                fg_send_result_fmt("{\"event\":\"status\",\"module\":\"%d\",\"state\":\"%d\",\"heap\":%lu,\"uptime\":%lu}",
                    g_activeModule, g_moduleState,
                    (unsigned long)ESP.getFreeHeap(),
                    (unsigned long)fg_uptime_secs());
            }
            else {
                fg_send_result_fmt("{\"event\":\"error\",\"msg\":\"Unknown command: %s\"}", cmd);
            }
        }
    }
}

// ============================================================
// Module launcher — creates a FreeRTOS task on Core 1
// ============================================================
bool fg_launch_module(FGModule mod, const char* ssid, const char* pass, uint8_t channel) {
    if (g_moduleState != STATE_IDLE) {
        fg_send_result("{\"event\":\"error\",\"msg\":\"Another module is running. Send stop first.\"}");
        return false;
    }

    ModuleLaunchParams* params = new ModuleLaunchParams();
    params->mod = mod;
    params->channel = channel;
    if (ssid) strncpy(params->ssid, ssid, 32);
    else params->ssid[0] = '\0';
    if (pass) strncpy(params->pass, pass, 64);
    else params->pass[0] = '\0';

    BaseType_t ok = xTaskCreatePinnedToCore(
        module_task_wrapper,
        "fg_module",
        FG_MODULE_TASK_STACK,
        params,
        FG_MODULE_TASK_PRIO,
        NULL,
        1  // Core 1
    );
    if (ok != pdPASS) {
        delete params;
        fg_send_result("{\"event\":\"error\",\"msg\":\"Failed to spawn module task\"}");
        return false;
    }
    return true;
}

// ============================================================
// Module task — runs the scan/attack on Core 1, then exits
// ============================================================
static void module_task_wrapper(void* param) {
    ModuleLaunchParams* p = (ModuleLaunchParams*)param;

    if (xSemaphoreTake(g_moduleMutex, pdMS_TO_TICKS(100)) != pdTRUE) {
        fg_send_result("{\"event\":\"error\",\"msg\":\"Module mutex busy\"}");
        delete p;
        vTaskDelete(NULL);
        return;
    }

    g_moduleState = STATE_RUNNING;
    g_activeModule = p->mod;
    g_stopRequested = false;

    Serial.printf("[Module] Starting module %d on Core %d\n", p->mod, xPortGetCoreID());

    switch (p->mod) {
        case MOD_WIFI_AP_SCAN:
            fg_ap_scan();
            break;
        case MOD_WIFI_CLIENT_SCAN:
            fg_client_scan(p->ssid, p->pass);
            break;
        case MOD_WIFI_ARP_SCAN:
            fg_arp_scan(p->ssid, p->pass);
            break;
        case MOD_WIFI_SNIFFER:
            fg_sniffer(p->channel);
            break;
        default:
            fg_send_result("{\"event\":\"error\",\"msg\":\"Module not implemented yet\"}");
            break;
    }

    g_moduleState = STATE_IDLE;
    g_activeModule = MOD_NONE;
    g_stopRequested = false;

    xSemaphoreGive(g_moduleMutex);
    delete p;

    Serial.printf("[Module] Done. Heap: %lu\n", (unsigned long)ESP.getFreeHeap());
    vTaskDelete(NULL);
}

// ============================================================
// WebSocket broadcast (called from ws_sender_task)
// ============================================================
void fg_ws_broadcast(const char* json) {
    ws.textAll(json);
}

// ============================================================
// WS Sender Task — drains result queue → WebSocket (Core 0)
// ============================================================
void fg_ws_sender_task(void* param) {
    FGResultMsg msg;
    for (;;) {
        if (xQueueReceive(g_resultQueue, &msg, pdMS_TO_TICKS(100)) == pdTRUE) {
            fg_ws_broadcast(msg.json);
            // Also echo to Serial for debugging
            Serial.printf("[Result] %s\n", msg.json);
        }
        ws.cleanupClients();
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

// ============================================================
// Server init & start
// ============================================================
void fg_web_server_init() {
    ws.onEvent(onWsEvent);
    server.addHandler(&ws);

    // Serve main page from PROGMEM
    server.on("/", HTTP_GET, [](AsyncWebServerRequest* request) {
        AsyncWebServerResponse* response = request->beginResponse_P(200, "text/html", index_html_gz, index_html_gz_len);
        response->addHeader("Content-Encoding", "gzip");
        request->send(response);
    });

    server.on("/style.css", HTTP_GET, [](AsyncWebServerRequest* request) {
        AsyncWebServerResponse* response = request->beginResponse_P(200, "text/css", style_css_gz, style_css_gz_len);
        response->addHeader("Content-Encoding", "gzip");
        request->send(response);
    });

    server.on("/app.js", HTTP_GET, [](AsyncWebServerRequest* request) {
        AsyncWebServerResponse* response = request->beginResponse_P(200, "application/javascript", app_js_gz, app_js_gz_len);
        response->addHeader("Content-Encoding", "gzip");
        request->send(response);
    });

    // 404
    server.onNotFound([](AsyncWebServerRequest* request) {
        request->redirect("/");
    });
}

void fg_web_server_start() {
    fg_web_server_init();
    server.begin();
    Serial.printf("[Web] Server started on port %d\n", FG_WEB_PORT);
    Serial.printf("[Web] WebSocket at ws://192.168.4.1%s\n", FG_WS_PATH);
}
