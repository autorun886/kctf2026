# Device Wi-Fi failover service

Root service for the Pixel 6 test device. On boot it restores the existing
Wi-Fi hotspot configuration. When the Wi-Fi station disconnects for two
consecutive checks, it enables Wi-Fi and tries every saved network in
networkId order for up to three complete rounds. A successful association
ends recovery immediately.

Device paths:

- Service: `/data/adb/service.d/wifi-failover.sh`
- Runtime files: `/data/adb/wifi-failover/`
- Log: `/data/adb/wifi-failover/wifi-failover.log`
- Settings: `/data/adb/wifi-failover/config.sh`

Useful checks:

```sh
su -c 'cat /data/adb/wifi-failover/wifi-failover.pid'
su -c 'tail -100 /data/adb/wifi-failover/wifi-failover.log'
su -c 'dumpsys tethering' | sed -n '/Tether state:/,/Upstream wanted:/p'
```
