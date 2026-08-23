#pragma once
// FireGod-ESP — Bad-BLE: advertises as a BLE HID keyboard. Once a target
// pairs/connects it types `text` (US layout) followed by ENTER, then idles.
// Empty text => a benign default demo string. Authorized testing only.
#include <Arduino.h>
void fg_bad_ble(const char* text);
