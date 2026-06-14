#pragma once
// ============================================================
// FireGod-ESP — Configuration
// ============================================================

#define FG_VERSION       "0.1.0"
#define FG_DEVICE_NAME   "FireGod-ESP"

// --- WiFi AP defaults ---
#define FG_AP_SSID       "ESP32-Shell"
#define FG_AP_PASS       "hacker1234"
#define FG_AP_CHANNEL    6
#define FG_AP_MAX_CONN   4

// --- Static IP for AP mode ---
#define FG_AP_IP         IPAddress(192, 168, 4, 1)
#define FG_AP_GATEWAY    IPAddress(192, 168, 4, 1)
#define FG_AP_SUBNET     IPAddress(255, 255, 255, 0)

// --- Hardware pins ---
#define FG_SPI_SCK       18
#define FG_SPI_MISO      19
#define FG_SPI_MOSI      23
#define FG_I2C_SDA       21
#define FG_I2C_SCL       22

// --- Serial ---
#define FG_SERIAL_BAUD   115200

// --- Web server ---
#define FG_WEB_PORT      80
#define FG_WS_PATH       "/ws"

// --- Scan limits ---
#define FG_MAX_APS       64
#define FG_MAX_CLIENTS   32
#define FG_MAX_ARP_HOSTS 254

// --- Sniffer ---
#define FG_SNIFF_MAX_DEV   80   // tracked unique devices
#define FG_SNIFF_EMIT_MS   1000 // stats/device flush interval to WebUI
#define FG_SNIFF_DEV_TTL   60000 // drop devices unseen this long (ms)

// --- FreeRTOS task config ---
#define FG_MODULE_TASK_STACK  8192
#define FG_SERIAL_TASK_STACK  4096
#define FG_WS_SENDER_STACK    4096
#define FG_MODULE_TASK_PRIO   2
#define FG_SERIAL_TASK_PRIO   1
#define FG_WS_SENDER_PRIO     3

// --- Result queue ---
#define FG_RESULT_QUEUE_SIZE  32
#define FG_RESULT_MSG_SIZE    512
