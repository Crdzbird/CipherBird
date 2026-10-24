#!/usr/bin/env bash
# Grants the showcase app the camera permission on an Android device as soon
# as the app is installed, so the Live entropy playground and its device test
# never wait on the system prompt. Run it in the background before
# `flutter run` or `flutter test`, or on its own after an install:
#   scripts/android/grant_camera.sh <device id> &
# It watches for up to ten minutes, grants once, and exits.
set -euo pipefail
DEVICE="${1:?usage: grant_camera.sh <adb device id>}"
APP="dev.cipherbird.cipherbird_example"
for _ in $(seq 1 600); do
    if adb -s "$DEVICE" shell pm list packages 2>/dev/null | grep -q "^package:$APP$"; then
        adb -s "$DEVICE" shell pm grant "$APP" android.permission.CAMERA >/dev/null 2>&1 || true
        if adb -s "$DEVICE" shell dumpsys package "$APP" | grep -A2 'android.permission.CAMERA' | grep -q 'granted=true'; then
            echo "camera granted to $APP on $DEVICE"
            exit 0
        fi
    fi
    sleep 1
done
echo "camera not granted: $APP did not appear on $DEVICE within ten minutes" >&2
exit 1
