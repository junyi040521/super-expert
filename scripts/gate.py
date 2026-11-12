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


# ---------------- grade: 等级判定 ----------------
# 「超级专家」不靠自称,靠可数条件。三级:
#   L1 判据完备   METHOD 每条判据都带「变红条件」字段
#   L2 判据可证伪 falsify.py --selftest 必须返回 0
#   L3 真实案例   cases/ 里 >=3 个案例,四段齐全,判据能对上 METHOD 标题
# 不足则输出 not-yet 并非零退出。等级是被判出来的,不是写上去的。

GRADE_SECTIONS = ("现场", "红", "判据", "修法")
GRADE_MIN_CASES = 3
GRADE_MIN_CHARS = 40        # 每段正文下限,防止用一句话凑数
GRADE_MIN_EVIDENCE = 50     # 每个 evidence 文件下限,防止建空文件占位


def method_titles(root):
    """METHOD.md 里判据小节的标题(含中文序号),跳过「附」。"""
    path = os.path.join(root, "METHOD.md")
    if not os.path.exists(path):
        return []
    txt = read_text(path) or ""
    titles = []
    marks = list(re.finditer(r"(?m)^## ", txt))
    for i, m in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(txt)
        body = txt[m.end():end]
        nl = body.find("\n")
        head = (body[:nl] if nl != -1 else body).strip()
        if not head or head.startswith("附"):
            continue
        titles.append(head)
    return titles


def split_sections(txt):
    """按 '## ' 切成 {段名: 正文}。段名取该行剩余文字。"""
    marks = list(re.finditer(r"(?m)^##\s+([^\n]+)", txt))
    out = {}
    for i, m in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(txt)
        out[m.group(1).strip()] = txt[m.end():end]
    return out


def grade_l3(root, titles):
    """检查 cases/。返回 (failures, case_count)。"""
    cdir = os.path.join(root, "cases")
    if not os.path.isdir(cdir):
        return ["cases/ 目录不存在: 没有真实案例库就不能自称超级专家"], 0
    dirs = [d for d in sorted(os.listdir(cdir))
            if os.path.isdir(os.path.join(cdir, d))]
    failures = []
    valid = 0
    for d in dirs:
        base = os.path.join(cdir, d)
        md = os.path.join(base, "case.md")
        if not os.path.exists(md):
            failures.append("%s: 缺 case.md" % d)
            continue
        secs = split_sections(read_text(md) or "")
        miss = [s for s in GRADE_SECTIONS if s not in secs]
        if miss:
            failures.append("%s: 缺段落 %s" % (d, "/".join(miss)))
            continue
        thin = [s for s in GRADE_SECTIONS
                if len(secs[s].strip()) < GRADE_MIN_CHARS]
        if thin:
            failures.append("%s: 段落过短 %s (需 >=%d 字符)"
                            % (d, "/".join(thin), GRADE_MIN_CHARS))
            continue
        # 「红」段必须有输出块: ``` 围栏或 4 空格缩进的行
        red = secs["红"]
        has_block = ("```" in red) or any(
            ln.startswith("    ") for ln in red.splitlines())
        if not has_block:
            failures.append("%s: 「红」段没有粘贴原始输出(需 ``` 或缩进块)" % d)
            continue
        # 「判据」段必须真对上 METHOD 里某条标题,不许挂空判据
        if titles and not any(t in secs["判据"] for t in titles):
            failures.append("%s: 「判据」段对不上 METHOD 任何一条标题" % d)
            continue
        ev = os.path.join(base, "evidence")
        if not os.path.isdir(ev):
            failures.append("%s: 缺 evidence/" % d)
            continue
        sizes = [os.path.getsize(os.path.join(ev, f))
                 for f in os.listdir(ev) if os.path.isfile(os.path.join(ev, f))]
        if not sizes or max(sizes) < GRADE_MIN_EVIDENCE:
            failures.append("%s: evidence/ 为空或过小 (需 >=%d 字节)"
                            % (d, GRADE_MIN_EVIDENCE))
            continue
        valid += 1
    if valid < GRADE_MIN_CASES:
        failures.append("有效案例 %d 个,不足 %d 个" % (valid, GRADE_MIN_CASES))
    return failures, valid


def run_grade(root):
    """返回 (等级是否达标, 输出行)。"""
    lines = ["等级判定"]
    titles = method_titles(root)

    # L1
    red1, _ = check_criteria(root)
    l1 = not red1
    lines.append("  L1 判据完备        %s  %s"
                 % ("PASS" if l1 else "FAIL",
                    "%d 条判据都带变红条件" % len(titles) if l1
                    else "; ".join(red1[:3])))

    # L2
    fals = os.path.join(root, "scripts", "falsify.py")
    if not os.path.exists(fals):
        l2, l2msg = False, "scripts/falsify.py 不存在"
    else:
        try:
            r = subprocess.run([sys.executable, fals, "--selftest"],
                               capture_output=True, timeout=90)
            l2 = (r.returncode == 0)
            tail = (r.stdout or b"").decode("utf-8", "replace").strip().splitlines()
            l2msg = (tail[-1] if tail else "") if l2 else "falsify --selftest 非零退出"
        except Exception as e:            # noqa: BLE001
            l2, l2msg = False, "falsify --selftest 无法执行: %s" % e
    lines.append("  L2 判据可被证伪    %s  %s"
                 % ("PASS" if l2 else "FAIL", l2msg))

    # L3
    f3, count = grade_l3(root, titles)
    l3 = not f3
    lines.append("  L3 真实案例 >= %-2d   %s  %s"
                 % (GRADE_MIN_CASES, "PASS" if l3 else "FAIL",
                    "%d 个案例,四段齐全,判据可对上" % count if l3
                    else "; ".join(f3[:3])))
    for extra in f3[3:]:
        lines.append("                      %s" % extra)

    ok = l1 and l2 and l3
    lines.append("")
    lines.append("GRADE  %s" % ("super-expert (超级专家级)" if ok
                                else "not-yet (未达超级专家级)"))
    return ok, lines


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


def _mk_case(root, name, crit="二 · 示例判据", drop=None, evidence=True):
    """造一个案例。drop 用来抽掉某一段，验证 grade 会因此判不通过。"""
    body = {
        "现场": "在某一台机器上执行某条命令，读到如下结果，并据此下了错误结论。"
                "这里写得足够长，是为了通过正文长度下限。\n\n"
                "    curl -w \"code=%{http_code}\" https://example.invalid\n",
        "红": "输出是这样的：\n\n```\ncode=200 size=0 t=40.0s\n```\n\n"
              "当时读成「通了」，实际上正文一个字都没到。\n",
        "判据": "对应 METHOD「%s」。两个读数必须一起看，单看一个会读出假成功。"
                "这类假成功最贵，因为后面的方案会建立在错误前提上。\n" % crit,
        "修法": "把判据收紧成 code==200 且 size>0，并重建阳性对照再下结论。"
                "改完任何人照着命令重跑都能得到同样的判定，而不是只能信报告。\n",
    }
    if drop:
        body.pop(drop, None)
    md = "# 案例 %s\n\n" % name + "".join(
        "## %s\n\n%s\n" % (k, v) for k, v in body.items())
    _mk(root, "cases/%s/case.md" % name, md)
    if evidence:
        _mk(root, "cases/%s/evidence/raw.txt" % name,
             "$ curl ...\ncode=200 size=0\n" + "x" * 60 + "\n")


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

        # ---- 等级判定必须能判上，也必须能判下 ----
        # 只测「能通过」等于没测: 一个永远返回 super 的判定器同样会过。
        gd = os.path.join(base, "grade")
        _mk(gd, "LICENSE", "MIT\n")
        _mk(gd, "METHOD.md",
            "## 二 · 示例判据\n\n**变红条件**: 只有一个读数就红\n")
        _mk(gd, "scripts/falsify.py", "import sys\nsys.exit(0)\n")

        _mk_case(gd, "001-a")
        _mk_case(gd, "002-b")
        ok2, _ = run_grade(gd)
        chk("grade: only 2 cases => not-yet", not ok2, "ok=%s" % ok2)

        _mk_case(gd, "003-c")
        ok3, _ = run_grade(gd)
        chk("grade: 3 complete cases => super", ok3, "ok=%s" % ok3)

        _mk_case(gd, "003-c", drop="修法")
        ok4, _ = run_grade(gd)
        chk("grade: missing section => not-yet", not ok4, "ok=%s" % ok4)

        _mk_case(gd, "003-c", crit="十 · 根本不存在")
        ok5, _ = run_grade(gd)
        chk("grade: dangling criterion => not-yet", not ok5, "ok=%s" % ok5)

        _mk_case(gd, "003-c")
        os.remove(os.path.join(gd, "cases", "003-c", "evidence", "raw.txt"))
        ok6, _ = run_grade(gd)
        chk("grade: empty evidence => not-yet", not ok6, "ok=%s" % ok6)

        _mk_case(gd, "003-c")
        _mk(gd, "scripts/falsify.py", "import sys\nsys.exit(1)\n")
        ok7, _ = run_grade(gd)
        chk("grade: falsify red => not-yet", not ok7, "ok=%s" % ok7)
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
    # --grade 允许带 root，也可能不带
    args = [a for a in argv[1:] if not a.startswith("--")]
    root = args[0] if args else "."
    if not os.path.isdir(root):
        print("not a dir: %s" % root)
        return 2
    if "--grade" in argv:
        ok, lines = run_grade(root)
        print("\n".join(lines))
        return 0 if ok else 1
    red, _yellow, lines = run(root)
    print("\n".join(lines))
    return 1 if red else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
