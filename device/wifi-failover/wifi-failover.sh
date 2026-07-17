#!/system/bin/sh

BASE_DIR=/data/adb/wifi-failover
JAR="$BASE_DIR/device-network-ctl.jar"
MAIN_CLASS=com.autorun.device.DeviceNetworkCtl
PID_FILE="$BASE_DIR/wifi-failover.pid"
LOG_FILE="$BASE_DIR/wifi-failover.log"

CHECK_INTERVAL_SEC=10
DISCONNECT_CONFIRMATIONS=2
MAX_ROUNDS=3
ATTEMPT_WAIT_SEC=15
ATTEMPT_POLL_SEC=3
HOTSPOT_RETRIES=3
HOTSPOT_RETRY_WAIT_SEC=5

if [ -f "$BASE_DIR/config.sh" ]; then
    . "$BASE_DIR/config.sh"
fi

rotate_log() {
    if [ -f "$LOG_FILE" ] && [ "$(wc -c < "$LOG_FILE")" -gt 524288 ]; then
        mv -f "$LOG_FILE" "$LOG_FILE.1"
    fi
}

log_message() {
    rotate_log
    echo "$(date '+%Y-%m-%d %H:%M:%S') [wifi-failover] $*" >> "$LOG_FILE"
}

cleanup() {
    rm -f "$PID_FILE"
    log_message "service stopped"
}

if [ -f "$PID_FILE" ]; then
    old_pid="$(cat "$PID_FILE" 2>/dev/null)"
    if [ -n "$old_pid" ] && kill -0 "$old_pid" 2>/dev/null; then
        exit 0
    fi
fi

echo $$ > "$PID_FILE"
trap cleanup EXIT INT TERM

run_helper() {
    CLASSPATH="$JAR" app_process /system/bin "$MAIN_CLASS" "$@"
}

hotspot_is_running() {
    dumpsys tethering 2>/dev/null \
        | grep -qE '^[[:space:]]+(ap_br_|softap|wlan)[^ ]* - TetheredState'
}

ensure_hotspot() {
    if hotspot_is_running; then
        log_message "hotspot already running"
        return 0
    fi

    attempt=1
    while [ "$attempt" -le "$HOTSPOT_RETRIES" ]; do
        log_message "starting hotspot attempt=$attempt/$HOTSPOT_RETRIES"
        helper_output="$(run_helper hotspot-start 2>&1)"
        helper_status=$?
        sleep "$HOTSPOT_RETRY_WAIT_SEC"
        if [ "$helper_status" -eq 0 ] || hotspot_is_running; then
            log_message "hotspot started"
            return 0
        fi
        log_message "hotspot start failed: $helper_output"
        attempt=$((attempt + 1))
    done

    log_message "hotspot start exhausted"
    return 1
}

wifi_is_connected() {
    cmd wifi status 2>/dev/null | grep -q '^Wifi is connected to '
}

saved_network_ids() {
    cmd wifi list-networks 2>/dev/null \
        | awk 'NR > 1 && $1 ~ /^[0-9][0-9]*$/ && !seen[$1]++ { print $1 }'
}

wait_for_wifi() {
    waited=0
    while [ "$waited" -lt "$ATTEMPT_WAIT_SEC" ]; do
        sleep "$ATTEMPT_POLL_SEC"
        if wifi_is_connected; then
            return 0
        fi
        waited=$((waited + ATTEMPT_POLL_SEC))
    done
    return 1
}

recover_wifi() {
    log_message "recovery started, max_rounds=$MAX_ROUNDS"
    cmd wifi set-wifi-enabled enabled >/dev/null 2>&1
    sleep 3
    if wifi_is_connected; then
        log_message "wifi recovered while enabling radio"
        return 0
    fi

    round=1
    while [ "$round" -le "$MAX_ROUNDS" ]; do
        cmd wifi start-scan >/dev/null 2>&1
        sleep 2
        network_ids="$(saved_network_ids)"
        if [ -z "$network_ids" ]; then
            log_message "round=$round no saved networks"
        fi

        for network_id in $network_ids; do
            log_message "round=$round/$MAX_ROUNDS trying networkId=$network_id"
            helper_output="$(run_helper wifi-connect "$network_id" 2>&1)"
            helper_status=$?
            if [ "$helper_status" -ne 0 ]; then
                log_message "networkId=$network_id helper failed: $helper_output"
                continue
            fi
            if wait_for_wifi; then
                current="$(cmd wifi status 2>/dev/null | sed -n 's/^Wifi is connected to /connected to /p' | head -n 1)"
                log_message "recovery succeeded networkId=$network_id $current"
                return 0
            fi
            log_message "networkId=$network_id timed out"
        done
        round=$((round + 1))
    done

    log_message "recovery exhausted after $MAX_ROUNDS rounds"
    return 1
}

log_message "service started pid=$$"
ensure_hotspot

disconnect_count=0
recovery_attempted=0
while true; do
    if wifi_is_connected; then
        if [ "$disconnect_count" -gt 0 ] || [ "$recovery_attempted" -ne 0 ]; then
            log_message "wifi connection healthy"
        fi
        disconnect_count=0
        recovery_attempted=0
    else
        disconnect_count=$((disconnect_count + 1))
        if [ "$disconnect_count" -ge "$DISCONNECT_CONFIRMATIONS" ] \
                && [ "$recovery_attempted" -eq 0 ]; then
            recovery_attempted=1
            recover_wifi
        fi
    fi
    sleep "$CHECK_INTERVAL_SEC"
done
