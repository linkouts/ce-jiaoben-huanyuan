# -*- coding: utf-8 -*-
# =====================================================================
#  CE .ct 官方混淆还原工具  v2.2  (完整修复版)
#  纯 Python 标准库，黑色控制台，拖文件即可
#
#  修复点：
#    1. 覆盖率阈值大幅放宽，主脚本再也不会被误判为“非记录层”
#    2. 一次处理表里所有 AssemblerScript（不再只解第一个）
#    3. 自动递归展开记录内部的 decodeFunction(Base85+zlib)
#    4. 正确把所有已还原脚本写回干净的 CT
#    5. 同时输出每个脚本的独立 .txt，方便直接看
#    6. v2.2 新增：还原所有 <Address> / <Offset> 字段（指针功能恢复）
#
#  用法：
#     1. 双击本文件（或 python CE_CT_Deobfuscator.py）
#     2. 把 .ct 拖进黑色窗口后回车
#     3. 结果保存在源文件同目录：
#           xxx_还原.ct          <- 可直接用 CE 打开
#           xxx_脚本.txt         <- 所有自动汇编脚本合并为一个文件
# =====================================================================

import os
import re
import sys
import zlib
import traceback
from collections import OrderedDict

# ---- 控制台编码保护 ----
for _name in ("stdout", "stderr"):
    _s = getattr(sys, _name, None)
    try:
        _s.reconfigure(errors="replace")
    except Exception:
        pass


# =====================================================================
#  自定义 Base85（与 CE 官方 decode_function 完全一致）
# =====================================================================
class CustomBase85(object):
    alphabet = ("0123456789"
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz"
                "!#$%()*+,-./:;=?@[]^_{}")
    powers = (52200625, 614125, 7225, 85, 1)

    @classmethod
    def is_base85(cls, s):
        if not s:
            return False
        return all(ch in cls.alphabet for ch in s)

    @classmethod
    def to_bin(cls, data):
        data = "".join(data.split())
        result = bytearray()
        size = len(data)
        for i in range(0, size, 5):
            chunk = data[i:i + 5]
            a = 0
            for j, ch in enumerate(chunk):
                idx = cls.alphabet.find(ch)
                if idx < 0:
                    raise ValueError("非法字符: %r" % ch)
                a += idx * cls.powers[j]
            if len(chunk) == 5:
                result.extend(a.to_bytes(4, "big"))
            else:
                rem = size % 5
                if rem in (2, 3, 4):
                    a += 84 + cls.powers[rem - 1]
                    result.extend(a.to_bytes(4, "big")[:rem - 1])
        return bytes(result)


def shift_minus1(raw):
    return bytes((b - 1) & 0xFF for b in raw)


def decode_layer(text):
    """一层官方混淆 = 自定义 Base85 解码 + 每个字节减 1"""
    out = shift_minus1(CustomBase85.to_bin(text))
    for enc in ("utf-8", "gbk", "latin-1"):
        try:
            return out.decode(enc)
        except Exception:
            continue
    return out.decode("latin-1")


def decode_lua(data):
    """decodeFunction 轻量混淆 = Base85 解码 + zlib 解压"""
    return zlib.decompress(CustomBase85.to_bin(data))


# =====================================================================
#  {O密钥}记录格式
# =====================================================================
# 注意：Base85 字母表本身包含 { 和 }，所以 payload 必须用 \S+ 匹配，
# 绝不能用 [^\s{}]+，否则长 payload 会被截断，decodeFunction 字符串残缺。
RECORD_RE = re.compile(r'\{O(\d+)\}(\S+)')


def decode_records(text, strict_coverage=False):
    """
    把 {O密钥}+Base85 记录还原成原始行列表。
    v2.1 改进：
      - 正则允许 payload 含 { }（官方字母表本身就有）
      - 覆盖率阈值大幅放宽，主脚本不再被误判
    """
    recs = RECORD_RE.findall(text)
    if not recs:
        return None

    covered = sum(len(m.group(0)) for m in RECORD_RE.finditer(text))
    text_len = len(text.strip())
    ratio = covered / max(1, text_len)

    # 原版 0.6 太严；现在只要找到 ≥ 2 条记录，或覆盖率 > 0.08 就尝试
    if strict_coverage and ratio < 0.6:
        return None
    if len(recs) < 2 and ratio < 0.08:
        return None

    lines = []
    fail_count = 0
    for _key, payload in recs:
        try:
            line = shift_minus1(CustomBase85.to_bin(payload)).decode("utf-8", "replace")
            lines.append(line)
        except Exception:
            fail_count += 1
            if fail_count > max(3, len(recs) // 3):
                return None
            lines.append("")  # 占位

    return lines


def expand_nested_decodefunction(text):
    """
    在已经还原的文本里继续展开 decodeFunction("...")
    支持嵌套多次。
    若 zlib 解压后是 Lua 编译字节码（不可读文本），则保留原 decodeFunction 调用，
    让 CE 运行时自己解码（这样 CT 仍然可用）。
    """
    DF_RE = re.compile(r'decodeFunction\s*\(\s*"([^"]{20,})"\s*\)', re.DOTALL)

    def _is_mostly_text(s):
        if not s:
            return False
        # 可打印字符 + 常见空白占比 > 85% 才认为是源码
        printable = sum(1 for c in s if c in "\n\r\t" or 32 <= ord(c) < 127 or ord(c) > 160)
        return printable / max(1, len(s)) > 0.85

    def _repl(m):
        payload = m.group(1)
        try:
            raw = decode_lua(payload)
            for enc in ("utf-8", "gbk", "latin-1"):
                try:
                    decoded = raw.decode(enc)
                    if _is_mostly_text(decoded):
                        return decoded
                    # 字节码 → 保留原调用
                    return m.group(0)
                except Exception:
                    continue
            # 最后尝试 latin-1
            decoded = raw.decode("latin-1", "replace")
            if _is_mostly_text(decoded):
                return decoded
            return m.group(0)
        except Exception:
            return m.group(0)

    for _ in range(5):
        new_text, n = DF_RE.subn(_repl, text)
        if n == 0:
            break
        text = new_text
    return text


def fully_decode_script_body(body):
    """
    对一段 AssemblerScript 内容做完整还原：
      1. 若本身是 Base85 → 先解一层
      2. 若解出后是 {O...} 记录 → 逐条还原
      3. 再展开内部 decodeFunction
    """
    body = body.strip()
    if not body:
        return body

    # 先尝试直接当 Base85 解
    if CustomBase85.is_base85(body[:80].replace("\n", "").replace("\r", "")):
        try:
            body = decode_layer(body)
        except Exception:
            pass

    # 记录层
    recs = decode_records(body)
    if recs is not None:
        body = "\n".join(recs)

    # 嵌套 decodeFunction
    body = expand_nested_decodefunction(body)

    # 再扫一次记录（有些 decodeFunction 解出来又是记录）
    recs2 = decode_records(body)
    if recs2 is not None:
        body = "\n".join(recs2)
        body = expand_nested_decodefunction(body)

    return body


# =====================================================================
#  载荷定位
# =====================================================================
OUTER_PATTERNS = [
    ("CheatTable x", r'<CheatTable[^>]*?\bx="([^"]{20,})"'),
    ("CheatEntries", r'<CheatEntries[^>]*>\s*([^<]{20,}?)\s*</CheatEntries>'),
    ("CheatEntry x", r'<CheatEntry[^>]*?\bx="([^"]{20,})"'),
    ("x attr", r'\bx="([^"]{40,})"'),
]


def find_outer_payload(text):
    for tag, pat in OUTER_PATTERNS:
        for m in re.finditer(pat, text, re.DOTALL):
            cand = m.group(1).strip()
            if CustomBase85.is_base85(cand):
                return tag, cand
    return None, None


def clean_for_print(s, limit=1200):
    s = "".join(ch if (ch in "\n\t" or ord(ch) >= 32) else " " for ch in s)
    s = re.sub(r"[ \t]{3,}", "  ", s)
    if len(s) > limit:
        s = s[:limit] + "\n... (过长已截断，完整内容见输出文件)"
    return s


# =====================================================================
#  地址 / 偏移 字段还原（指针功能关键）
# =====================================================================
def decode_address_or_offset(value):
    """
    CE 官方混淆也会把 <Address> 和 <Offset> 的内容用同一套
    Base85 + 每字节 -1 加密。尝试解码，失败则原样返回。
    """
    value = (value or "").strip()
    if not value:
        return value
    # 不是 Base85 字符集就不动
    if not CustomBase85.is_base85(value):
        return value
    try:
        decoded = decode_layer(value)
    except Exception:
        return value
    # 解码结果必须是可打印文本
    if not decoded or any(ord(c) < 32 and c not in "\t" for c in decoded):
        return value
    if len(decoded) > 200:
        return value
    return decoded


def restore_addresses_and_offsets(xml_text):
    """
    把 CT 里所有被混淆的 <Address> 和 <Offset> 还原。
    返回 (新文本, 成功还原数量)
    """
    count = [0]

    def _repl_addr(m):
        raw = m.group(1)
        fixed = decode_address_or_offset(raw)
        if fixed != raw:
            count[0] += 1
        return "<Address>" + fixed + "</Address>"

    def _repl_off(m):
        raw = m.group(1)
        fixed = decode_address_or_offset(raw)
        if fixed != raw:
            count[0] += 1
        return "<Offset>" + fixed + "</Offset>"

    text = re.sub(r"<Address>([^<]*)</Address>", _repl_addr, xml_text)
    text = re.sub(r"<Offset>([^<]*)</Offset>", _repl_off, text)
    return text, count[0]


# =====================================================================
#  拼回干净 CT
# =====================================================================
def build_clean_ct(xml_text, script_map):
    """
    xml_text  : 已经剥除外层混淆的 XML 字符串
    script_map: {原始混淆内容: 还原后内容}  用于替换所有 AssemblerScript
    """
    body = xml_text

    # 1) 替换每一个 AssemblerScript
    def _replace_asm(m):
        open_tag = m.group(1)
        old_body = m.group(2)
        close_tag = m.group(3)
        new_body = script_map.get(old_body.strip(), old_body)
        if new_body.count("{O") > 5 and new_body.count("{O") > len(new_body) // 50:
            return m.group(0)
        return open_tag + "\n" + new_body.strip() + "\n" + close_tag

    body = re.sub(
        r'(<AssemblerScript[^>]*>)(.*?)(</AssemblerScript>)',
        _replace_asm,
        body,
        flags=re.DOTALL
    )

    # 2) 还原所有 Address / Offset 字段（指针功能的关键）
    body, addr_count = restore_addresses_and_offsets(body)
    # addr_count 通过闭包外的变量传出不太方便，这里直接挂到函数属性上
    build_clean_ct.last_addr_count = addr_count

    # 3) 清理无用属性
    body = re.sub(r'\s+rnd="\d+"', '', body)
    body = re.sub(r'\s+obfuscated="1"', '', body)
    body = re.sub(r'\s+z="1"', '', body)

    # 4) 保证有完整的 CheatTable 外壳
    if "<CheatTable" not in body:
        if "<CheatEntries" in body:
            body = ('<CheatTable CheatEngineTableVersion="52">\n'
                    + body + '\n</CheatTable>')
        else:
            body = ('<CheatTable CheatEngineTableVersion="52">\n'
                    '<CheatEntries>\n' + body + '\n</CheatEntries>\n'
                    '</CheatTable>')

    if not body.lstrip().startswith("<?xml"):
        body = '<?xml version="1.0" encoding="utf-8"?>\n' + body

    return body


# =====================================================================
#  控制台辅助
# =====================================================================
def hold(msg="\n按回车继续，输入 q 回车退出: "):
    try:
        ans = input(msg)
    except EOFError:
        print("(输入结束，程序退出)")
        return "q"
    return (ans or "").strip().lower()


def split_paths(line):
    line = (line or "").strip()
    if not line:
        return []
    out, buf, quote = [], "", None
    for ch in line:
        if quote:
            if ch == quote:
                quote = None
            else:
                buf += ch
        elif ch in ('"', "'"):
            quote = ch
        elif ch == " ":
            if buf:
                out.append(buf)
                buf = ""
        else:
            buf += ch
    if buf:
        out.append(buf)
    return out


EXTS = (".ct", ".txt", ".xml")


def collect_files(paths):
    files = []
    for p in paths:
        p = p.strip().strip('"').strip("'")
        if not p:
            continue
        if os.path.isdir(p):
            for name in sorted(os.listdir(p)):
                if name.lower().endswith(EXTS):
                    files.append(os.path.join(p, name))
        elif os.path.isfile(p):
            files.append(p)
        else:
            print("  [跳过] 路径不存在: %s" % p)
    return files


# =====================================================================
#  主处理
# =====================================================================
def process(path, max_depth=12):
    print("")
    print("=" * 66)
    print("处理: %s" % path)
    print("=" * 66)

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    print("读取成功: %d 字符" % len(text))

    stem, _ext = os.path.splitext(path)
    out_ct = stem + "_还原.ct"

    history = [text]
    current = text

    # ---------- 阶段1：剥外层混淆（CheatTable x / CheatEntries 等） ----------
    for depth in range(1, max_depth + 1):
        tag, payload = find_outer_payload(current)
        if not payload:
            print("第 %d 层: 外层已无混淆载荷。" % depth)
            break

        print("第 %d 层: 发现 %s 载荷 (%d 字符)，解码中..." % (depth, tag, len(payload)))
        try:
            nxt = decode_layer(payload)
        except Exception as e:
            print("   Base85+每字节-1 失败(%s)，尝试 zlib 分支..." % e)
            try:
                nxt = decode_lua(payload).decode("utf-8", "replace")
            except Exception as e2:
                print("   这一层解不出来: %s" % e2)
                break

        preview = clean_for_print(nxt, 180).replace("\n", "\n   ")
        print("   解出 %d 字符，预览:\n   %s" % (len(nxt), preview))
        history.append(nxt)
        current = nxt

    # 取最深的 XML 作为基础
    base_xml = None
    for layer in reversed(history):
        if "<CheatEntry" in layer or "<CheatEntries" in layer or "<CheatTable" in layer:
            base_xml = layer
            break
    if base_xml is None:
        base_xml = history[-1]

    # ---------- 阶段2：处理所有 AssemblerScript ----------
    print("\n开始处理所有 AssemblerScript ...")
    asm_pattern = re.compile(
        r'(<AssemblerScript[^>]*>)(.*?)(</AssemblerScript>)',
        re.DOTALL
    )
    matches = list(asm_pattern.finditer(base_xml))
    print("共发现 %d 个 AssemblerScript" % len(matches))

    script_map = OrderedDict()   # 原始body -> 还原body
    script_list = []             # 用于写合并 txt

    for idx, m in enumerate(matches, 1):
        old_body = m.group(2)
        print("  [%02d/%d] 长度 %d ..." % (idx, len(matches), len(old_body)), end="")
        try:
            new_body = fully_decode_script_body(old_body)
            script_map[old_body.strip()] = new_body
            script_list.append(new_body)

            # 判断还原质量
            if "{O" in new_body[:300] and new_body.count("{O") > 3:
                print(" 仍有记录残留")
            elif "decodeFunction" in new_body and "{$lua}" in new_body:
                print(" OK (含编译 Lua，已保留 decodeFunction 供 CE 运行时解码)")
            elif "decodeFunction" in new_body:
                print(" OK (保留 decodeFunction)")
            else:
                preview_lines = [
                    ln for ln in new_body.splitlines()
                    if ln.strip() and not ln.strip().startswith("{$")
                ]
                preview = " | ".join(preview_lines[:3])[:90]
                print(" OK  →  %s" % preview)
        except Exception as e:
            print(" 失败: %s" % e)
            script_map[old_body.strip()] = old_body
            script_list.append(old_body)

    # ---------- 阶段3：生成干净 CT ----------
    clean = build_clean_ct(base_xml, script_map)
    addr_n = getattr(build_clean_ct, "last_addr_count", 0)
    if addr_n:
        print("\n已还原 %d 个 Address/Offset 字段（指针可用）" % addr_n)
    else:
        print("\n未发现需要还原的 Address/Offset 字段")

    try:
        with open(out_ct, "w", encoding="utf-8") as f:
            f.write(clean)
        print("[已保存] %s" % out_ct)
    except Exception:
        print("保存 CT 失败:\n" + traceback.format_exc())

    # ---------- 阶段4：所有脚本合并存为一个 txt ----------
    out_txt = stem + "_脚本.txt"
    try:
        with open(out_txt, "w", encoding="utf-8") as f:
            for i, body in enumerate(script_list, 1):
                f.write("===== 脚本 %02d =====\n" % i)
                f.write(body.rstrip() + "\n\n")
        print("[已保存] %s" % out_txt)
    except Exception:
        print("保存脚本文件失败")

    # ---------- 打印最重要的几个脚本预览 ----------
    print("\n" + "=" * 66)
    print("还原完成，共处理 %d 个脚本。下面是前几个脚本的开头预览：" % len(script_list))
    print("=" * 66)
    for i, body in enumerate(script_list[:5], 1):
        print("\n----- 脚本 %02d -----" % i)
        for ln in body.splitlines()[:18]:
            print("| " + ln)
        if body.count("\n") > 18:
            print("| ...")
    if len(script_list) > 5:
        print("\n（还有 %d 个脚本已写入合并 txt 文件）" % (len(script_list) - 5))

    print("\n说明：")
    print("  · {$NOPROLOGUE} / {$lua} 是 CE 内部标记，可保留或删除，不影响功能。")
    print("  · 若合并文件中某段脚本仍有大量 {O...} 残留，可单独复制出来用本工具二次处理。")
    print("  · 生成的 _还原.ct 可直接用 Cheat Engine 7.7+ 打开。")


def main():
    print("=" * 66)
    print("  CE .ct 官方混淆还原工具  v2.2  (完整修复版)")
    print("  Python %s  (纯标准库)" % sys.version.split()[0])
    print("-" * 66)
    print("  用法：")
    print("    1) 把 .ct 文件拖到本窗口后按回车")
    print("    2) 可一次拖多个文件，或拖整个文件夹")
    print("    3) 结果保存在源文件同目录")
    print("    输入 q 回车 = 退出")
    print("=" * 66)

    if len(sys.argv) > 1:
        for p in collect_files(sys.argv[1:]):
            try:
                process(p)
            except Exception:
                print("处理出错:\n" + traceback.format_exc())
        hold()
        return

    while True:
        try:
            line = input("\n请把文件拖到本窗口后按回车 > ")
        except EOFError:
            print("(输入结束，程序退出)")
            return
        if (line or "").strip().lower() == "q":
            print("已退出。")
            return
        files = collect_files(split_paths(line))
        if not files:
            print("没识别到有效文件，请重新拖入 (输入 q 退出)。")
            continue
        for p in files:
            try:
                process(p)
            except Exception:
                print("处理出错:\n" + traceback.format_exc())
        print("\n本轮共处理 %d 个文件。" % len(files))
        if hold() == "q":
            print("已退出。")
            return


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("\n程序发生异常：")
        traceback.print_exc()
        hold()
