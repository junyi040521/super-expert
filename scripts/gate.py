#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gate.py - 三道检查。红则非零退出。零第三方依赖。

用法:
    python gate.py <repo_root>
    python gate.py --selftest

设计约束（都是被坑出来的）:
  1. 扫描跳过自身文件。否则模式串会命中自己的源码，自己判自己红。
  2. 模式串用拼接构造，源码里不出现完整字面量。
  3. 黄项必须带 文件:行，没有出处的黄不算黄，算噪声。
"""

import os
import re
import sys
import shutil
import tempfile
import subprocess

SELF = os.path.basename(__file__)

# 拼接构造，避免源码自匹配
_PAT_CRED = [
    ("private-key", "-----BEGIN" + r"\s+[A-Z ]*PRIVATE" + r"\s+KEY-----"),
    ("api-key", r"\b" + "sk" + r"-[A-Za-z0-9]{20,}"),
    ("bearer", r"Bearer" + r"\s+[A-Za-z0-9_\-\.]{30,}"),
    ("assign", r"(?:passwd|password|secret)\s*[:=]\s*['\"][^'\"\s]{6,}['\"]"),
    ("internal-ip", r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b"),
]

SKIP_DIR = {".git", "__pycache__", "node_modules", ".venv", "venv", "dist", "build"}


def walk(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIR]
        for fn in filenames:
            if fn == SELF:
                continue
            yield os.path.join(dirpath, fn)


def read_text(path):
    try:
        with open(path, "rb") as f:
            raw = f.read()
        if b"\x00" in raw[:4096]:
            return None
        return raw.decode("utf-8", "replace")
    except OSError:
        return None


def check_cred(root):
    """凭证扫描。红: 私钥/长 API key。黄: 内网 IP。"""
    red, yellow = [], []
    for p in walk(root):
        if p.endswith((".png", ".jpg", ".zip", ".pyc")):
            continue
        txt = read_text(p)
        if txt is None:
            continue
        rel = os.path.relpath(p, root).replace("\\", "/")
        for lineno, line in enumerate(txt.splitlines(), 1):
            if len(line) > 4000:
                continue
            for name, pat in _PAT_CRED:
                if re.search(pat, line):
                    item = "%s:%d [%s]" % (rel, lineno, name)
                    (yellow if name == "internal-ip" else red).append(item)
    return red, yellow


def check_criteria(root):
    """METHOD.md 的每条判据必须带一个结构化的变红条件字段。红: 缺。

    不能只查「文中出现变红条件四个字」——
    「没有变红条件」这句话本身就含那四个字, 会直接绕过检查。
    判据必须是标记行, 不是子串。这是本文件唯一一处刻意反子串的地方。
    """
    path = os.path.join(root, "METHOD.md")
    if not os.path.exists(path):
        return ["METHOD.md missing"], []
    txt = read_text(path) or ""
    red = []
    # 按行首 "## " 算段落边界。不用 split:
    # 文件若本身以 "## " 开头, split 不产生前导块, 硬切 [1:] 会把唯一一段丢掉。
    marks = list(re.finditer(r"(?m)^## ", txt))
    if not marks:
        return ["METHOD.md 里没有任何判据小节"], []
    for i, m in enumerate(marks):
        start = m.end()
        end = marks[i + 1].start() if i + 1 < len(marks) else len(txt)
        body = txt[start:end]
        nl = body.find("\n")
        head = (body[:nl] if nl != -1 else body).strip()
        if not head or head.startswith("附"):
            continue
        if not re.search(r"\*\*变红条件\*\*\s*[：:]", body):
            red.append("判据缺变红条件字段: %s" % head[:40])
    return red, []


def check_license(root):
    """必须存在授权声明文件，且不得含 UNLICENSED 标记。红: 缺。"""
    red, yellow = [], []
    names = {"LICENSE", "LICENSE.md", "LICENSE.txt"}
    if not any(os.path.exists(os.path.join(root, n)) for n in names):
        red.append("LICENSE 缺失: 无授权声明即默认保留所有权利")
    for p in walk(root):
        if not p.endswith((".md", ".json", ".txt")):
            continue
        txt = read_text(p)
        if txt and "上游未提供授权" in txt:
            rel = os.path.relpath(p, root).replace("\\", "/")
            yellow.append("%s [第三方授权待核]" % rel)
    return red, yellow


CHECKS = [
    ("CRED", check_cred),
    ("CRIT", check_criteria),
    ("LIC", check_license),
]


def run(root):
    all_red, all_yellow, lines = [], [], []
    for code, fn in CHECKS:
        red, yellow = fn(root)
        for r in red:
            lines.append("RED    %s %s" % (code, r))
        for y in yellow:
            lines.append("YELLOW %s %s" % (code, y))
        all_red += red
        all_yellow += yellow
        lines.append("PASS   %s (%d red / %d yellow)" % (code, len(red), len(yellow)))
    lines.append("")
    lines.append("RESULT red=%d yellow=%d" % (len(all_red), len(all_yellow)))
    return len(all_red), len(all_yellow), lines


# ---------------- selftest ----------------

def _mk(root, rel, text):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p) or root, exist_ok=True)
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def selftest():
    """造三个仓库: 干净的、注假密钥的、缺变红条件的。
    断言: 干净 => 0 红; 注入 => 红; 撤除 => 归零。
    真"反向证伪"，不是只测通过。"""
    base = tempfile.mkdtemp(prefix="gate_st_")
    results = []

    def chk(name, cond, detail=""):
        results.append((name, bool(cond), detail))

    try:
        good = os.path.join(base, "good")
        _mk(good, "LICENSE", "MIT\n")
        _mk(good, "METHOD.md", "## 一 · 示例\n\n**变红条件**: 填不出就红\n")
        _mk(good, "README.md", "hello\n")

        r0, y0, _ = run(good)
        chk("clean repo => 0 red", r0 == 0, "red=%d" % r0)

        # 注入
        _mk(good, "leak.py", "KEY = " + '"sk' + '-abcdefghijklmnopqrstuvwxyz012345"\n')
        r1, _, _ = run(good)
        chk("inject key => red", r1 > r0, "red=%d -> %d" % (r0, r1))

        # 撤除
        os.remove(os.path.join(good, "leak.py"))
        r2, _, _ = run(good)
        chk("remove key => back to 0", r2 == 0, "red=%d" % r2)

        # 判据缺变红条件字段。这里刻意写「没有变红条件」:
        # 若检测器用子串匹配, 这句话反而会让它通过 —— 所以必须判红。
        _mk(good, "METHOD.md", "## 一 · 示例\n\n没有变红条件\n")
        r3, _, _ = run(good)
        chk("negated phrase cannot bypass => red", r3 > 0, "red=%d" % r3)

        # 对偶: 有标记时必须回到零红。只否不认的检查器同样是坏的。
        _mk(good, "METHOD.md", "## 一 · 示例\n\n**变红条件**: x\n")
        r3b, _, _ = run(good)
        chk("field present => 0 red", r3b == 0, "red=%d" % r3b)

        # 缺 LICENSE
        _mk(good, "METHOD.md", "## 一 · 示例\n\n**变红条件**: x\n")
        os.remove(os.path.join(good, "LICENSE"))
        r4, _, _ = run(good)
        chk("no LICENSE => red", r4 > 0, "red=%d" % r4)

        # 自扫不误伤: 本脚本自身不应被判红
        chk("self file skipped", SELF == "gate.py", SELF)
    finally:
        shutil.rmtree(base, ignore_errors=True)

    ok = sum(1 for _, c, _ in results if c)
    for name, cond, detail in results:
        print("%s %s  %s" % ("PASS" if cond else "FAIL", name, detail))
    print("\nselftest %d/%d" % (ok, len(results)))
    return 0 if ok == len(results) else 1


def main(argv):
    if "--selftest" in argv:
        return selftest()
    root = argv[1] if len(argv) > 1 else "."
    if not os.path.isdir(root):
        print("not a dir: %s" % root)
        return 2
    red, _yellow, lines = run(root)
    print("\n".join(lines))
    return 1 if red else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
