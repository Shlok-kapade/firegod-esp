#pragma once
// ============================================================
// FireGod-ESP — Web Server + WebSocket
// ============================================================

#include <ESPAsyncWebServer.h>
#include "fg_globals.h"

void fg_web_server_init();
void fg_web_server_start();
void fg_ws_broadcast(const char* json);

// Spawn a module on its own task (Core 1), mutex-guarded. Safe to call from the
// serial shell so long-running modules don't block the shell task.
// Returns false if another module is already running.
bool fg_launch_module(FGModule mod, const char* ssid = nullptr,
                      const char* pass = nullptr, uint8_t channel = 0,
                      bool flag = false, const char* list = nullptr);

// Task: drains g_resultQueue and broadcasts via WebSocket
void fg_ws_sender_task(void* param);
