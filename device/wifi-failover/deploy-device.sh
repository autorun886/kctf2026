#!/system/bin/sh

set -eu

STAGE=/data/local/tmp/wifi-failover-stage
BASE=/data/adb/wifi-failover
SERVICE=/data/adb/service.d/wifi-failover.sh

if [ -f "$BASE/wifi-failover.pid" ]; then
    old_pid="$(cat "$BASE/wifi-failover.pid" 2>/dev/null || true)"
    if [ -n "$old_pid" ]; then
        kill "$old_pid" 2>/dev/null || true
        sleep 1
    fi
fi

mkdir -p "$BASE" /data/adb/service.d
cp "$STAGE/device-network-ctl.jar" "$BASE/device-network-ctl.jar"
cp "$STAGE/wifi-failover.sh" "$BASE/wifi-failover.sh"
cp "$STAGE/config.sh" "$BASE/config.sh"
cp "$STAGE/service.d-wifi-failover.sh" "$SERVICE"

chown 0:0 "$BASE/device-network-ctl.jar" "$BASE/wifi-failover.sh" \
    "$BASE/config.sh" "$SERVICE"
chmod 700 "$BASE/wifi-failover.sh" "$SERVICE"
chmod 600 "$BASE/device-network-ctl.jar" "$BASE/config.sh"

nohup "$SERVICE" >/dev/null 2>&1 </dev/null &
