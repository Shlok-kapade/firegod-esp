// ============================================================
// FireGod-ESP — Entrypoint
// Boots SoftAP, web server + WebSocket, serial shell, and the
// background tasks. All real work runs in FreeRTOS tasks; loop()
// is just a heartbeat.
// ============================================================

#include <Arduino.h>
#include "config.h"
#include "fg_globals.h"
#include "core/wifi_manager.h"
#include "core/web_server.h"
#include "core/serial_shell.h"

void setup() {
    Serial.begin(FG_SERIAL_BAUD);
    delay(200);
    g_bootTime = millis();

    Serial.println();
    Serial.println("============================================");
    Serial.printf ("  FireGod-ESP v%s booting...\n", FG_VERSION);
    Serial.println("============================================");

    // --- Result queue + module mutex (must exist before any task) ---
    g_resultQueue = xQueueCreate(FG_RESULT_QUEUE_SIZE, sizeof(FGResultMsg));
    if (!g_resultQueue) {
        Serial.println("[FATAL] Failed to create result queue!");
    }
    g_moduleMutex = xSemaphoreCreateMutex();
    if (!g_moduleMutex) {
        Serial.println("[FATAL] Failed to create module mutex!");
    }

    // --- WiFi: clean init then start SoftAP ---
    fg_wifi_init();
    fg_wifi_start_ap();

    // --- Web server + WebSocket ---
    fg_web_server_start();

    // --- Serial shell banner ---
    fg_serial_shell_init();

    // --- Background tasks ---
    // WS sender drains the result queue -> ws.textAll on Core 0
    // (same core as the AsyncTCP stack to avoid cross-core TX races).
    xTaskCreatePinnedToCore(
        fg_ws_sender_task, "fg_ws_sender",
        FG_WS_SENDER_STACK, nullptr, FG_WS_SENDER_PRIO, nullptr, 0);

    // Serial shell parser on Core 1 (alongside module tasks).
    xTaskCreatePinnedToCore(
        fg_serial_shell_task, "fg_serial_shell",
        FG_SERIAL_TASK_STACK, nullptr, FG_SERIAL_TASK_PRIO, nullptr, 1);

    Serial.printf("[Boot] Ready. Free heap: %lu bytes\n",
                  (unsigned long)ESP.getFreeHeap());
}

void loop() {
    // Lightweight heartbeat; periodic health log every ~30s.
    static unsigned long lastBeat = 0;
    unsigned long now = millis();
    if (now - lastBeat >= 30000) {
        lastBeat = now;
        Serial.printf("[HB] uptime=%lus heap=%lu clients=%d module=%d\n",
                      (unsigned long)fg_uptime_secs(),
                      (unsigned long)ESP.getFreeHeap(),
                      WiFi.softAPgetStationNum(),
                      (int)g_activeModule);
    }
    vTaskDelay(pdMS_TO_TICKS(1000));
}
