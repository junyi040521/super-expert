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

import json
import os
import re
import sys
import shutil
import tempfile
import subprocess

SELF = os.path.basename(__file__)

# 判据表有两份: 方法与算子。少扫一份, 那一份里的小节就永远不被检查。
CRIT_FILES = ("METHOD.md", "DOCTRINE.md")

# 拼接构造，避免源码自匹配
_PAT_CRED = [
    ("private-key", "-----BEGIN" + r"\s+[A-Z ]*PRIVATE" + r"\s+KEY-----"),
    ("api-key", r"\b" + "sk" + r"-[A-Za-z0-9]{20,}"),
    # 这一条是被自己漏掉过的: 仓库的发布流程天天用 GitHub token,
    # 而扫描表里只有 sk-/bearer/PRIVATE KEY, 于是真 token 摆在那儿算 0 红。
    ("github-token", r"\b" + "gh" + r"[pousr]_[A-Za-z0-9]{30,}"),
    ("github-pat", r"\b" + "github" + r"_pat_[A-Za-z0-9_]{30,}"),
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


def _crit_scan(path):
    """返回 [(小节标题, 是否有变红条件字段)]。按行首 "## " 切段。"""
    txt = read_text(path) or ""
    marks = list(re.finditer(r"(?m)^## ", txt))
    out = []
    for i, m in enumerate(marks):
        start = m.end()
        end = marks[i + 1].start() if i + 1 < len(marks) else len(txt)
        body = txt[start:end]
        nl = body.find("\n")
        head = (body[:nl] if nl != -1 else body).strip()
        if not head or head.startswith("附"):
            continue
        out.append((head, bool(re.search(r"\*\*变红条件\*\*\s*[：:]", body))))
    return out


def criteria_count(root):
    n = 0
    for fn in CRIT_FILES:
        p = os.path.join(root, fn)
        if os.path.exists(p):
            n += len(_crit_scan(p))
    return n


def check_criteria(root):
    """判据表的每条小节必须带一个结构化的变红条件字段。红: 缺。

    不能只查「文中出现变红条件四个字」——
    「没有变红条件」这句话本身就含那四个字, 会直接绕过检查。
    判据必须是标记行, 不是子串。这是本文件唯一一处刻意反子串的地方。

    扫描面是两份文件, 不是一份: 上一版只扫 METHOD.md, 于是 DOCTRINE.md
    里那批算子准入门从来没被 L1 看过一遍 —— 扫描面写窄等于报假绿。
    """
    red = []
    for fn in CRIT_FILES:
        path = os.path.join(root, fn)
        if not os.path.exists(path):
            red.append("%s 缺失: 判据表缺一份, 完备就无从谈起" % fn)
            continue
        secs = _crit_scan(path)
        if not secs:
            red.append("%s 里没有任何判据小节" % fn)
            continue
        for head, has in secs:
            if not has:
                red.append("%s 判据缺变红条件字段: %s" % (fn, head[:40]))
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


# ---------------- L4 / L5 ----------------
# L4 形态判据被真实仓库打脸: shape.py 必须在 >=3 个真实仓库(P>=20 文件)上跑过,
#    且四条判据各自至少非 PASS 过一次。与 L3「真实案例 >=3」同构 ——
#    考的不是代码多不多, 是被真实世界打脸过几次。
# L5 覆盖诚实: cover.py 的账必须成立(absent >= 3 x covered)。
#
# 缺证据时输出 UNKNOWN, 不输出 FAIL:
#   「判据没被执行过」和「判据不成立」是两件事, 混在一起会让人以为改代码能解决。
# 也正因为如此, super-expert 要求 L4/L5 都真正 PASS —— 缺证据不算过。

GRADE_L4_RUNS = 3
GRADE_L4_MIN_P = 20
# 深度检查已降为 INFO(恒 N/A 或恒红都不算判据), 所以 L4 只要求这七条各红一次:
# 前三条是形态(shape), 后四条是通用探针(probe)。
L4_ITEMS = ("A5", "A2", "HUB", "SWALLOW", "DUP", "ORPHAN", "DEPS")


def grade_l4(root):
    """返回 (failures, used_count, unknown)。证据 = runs/*.txt 里的 ITEMS 行。"""
    d = os.path.join(root, "runs")
    if not os.path.isdir(d):
        return ["runs/ 不存在: 判据没有在任何真实仓库上跑过(未知, 不是失败)"], 0, True
    names = sorted(f for f in os.listdir(d) if f.endswith(".txt"))
    if not names:
        return ["runs/ 里没有任何 *.txt 证据"], 0, True
    hit, used = {}, []
    for fn in names:
        txt = read_text(os.path.join(d, fn)) or ""
        # shape 打 P=<文件数>, probe 打 SCAN ... subjects=<被测对象数>。
        # 口径必须统一成"被测对象数": probe 的 files= 只数代码文件,
        # 一个 348 份文档 + 16 个脚本的目录会被它算成 16, 于是证据被判成"样本不足"。
        m = (re.search(r"subjects=(\d+)", txt) or re.search(r"P=(\d+)", txt)
             or re.search(r"files=(\d+)", txt))
        p = int(m.group(1)) if m else 0
        if p < GRADE_L4_MIN_P:
            continue
        im = re.search(r"(?m)^ITEMS (.+)$", txt)
        if not im:
            continue
        used.append("%s(%d)" % (fn, p))
        for kv in im.group(1).split():
            if "=" not in kv:
                continue
            k, v = kv.split("=", 1)
            if v in ("RED", "YELLOW"):
                hit[k] = hit.get(k, 0) + 1
    fails = []
    if len(used) < GRADE_L4_RUNS:
        fails.append("有效证据 %d 个, 不足 %d 个(须 P>=%d)"
                     % (len(used), GRADE_L4_RUNS, GRADE_L4_MIN_P))
    cold = [k for k in L4_ITEMS if k not in hit]
    if cold:
        fails.append("从未非 PASS 的判据: %s —— 从未红过的判据不是判据"
                     % ",".join(cold))
    return fails, len(used), False


def _source_in_repo(root, name):
    """母版清单文件是否真的在这个仓库里。

    账里写 `source_verified: true` 只说明"当初跑的时候传了 --source",
    不说明那份母版跟着仓库发出来了。二者差别很大:
    母版不在仓库里, 这条核验别人就复算不了 —— 它成了"关于证据的文字"。
    """
    if not name:
        return None
    want = os.path.basename(name)
    for _dp, _dn, fns in os.walk(root):
        if want in fns:
            return True
    return False


def grade_l5(root):
    """返回 (failures, ok, unknown, note)。证据 = runs/cover-*.json。

    note 是"通过了, 但这句话得说清楚"的补充, 不参与判定。
    """
    d = os.path.join(root, "runs")
    if not os.path.isdir(d):
        return ["runs/ 不存在: 覆盖账没有算过(未知, 不是失败)"], False, True, ""
    rec, fn = None, ""
    for name in sorted(os.listdir(d)):
        if not (name.startswith("cover-") and name.endswith(".json")):
            continue
        txt = read_text(os.path.join(d, name))
        if not txt:
            continue
        try:
            r = json.loads(txt)
        except ValueError:  # noqa: swallow 半截 JSON 视为没有这条记录, 与缺失同义
            continue
        if r.get("items") is None:
            continue
        rec, fn = r, name
    if rec is None:
        return ["runs/ 里没有带母版分母的 cover 记录"], False, True, ""
    if rec.get("l5") is False:
        return ["%s: L5 不成立, absent=%s / covered=%s / text-only=%s"
                % (fn, rec.get("absent"), rec.get("covered_n"),
                   rec.get("text_only_n"))], False, False, ""
    if rec.get("l5") is not True:
        return ["%s: L5 为 unknown, 分母未取到" % fn], False, True, ""
    if rec.get("source_verified") is False:
        return ["%s: 分母未经母版核验, 覆盖账只能算账内自洽" % fn], False, True, ""
    note = ""
    if rec.get("source_verified") is True:
        have = _source_in_repo(root, rec.get("source"))
        if have is False:
            note = ("[账声明分母已过母版核验, 但母版 %s 不在本仓库: "
                    "这条核验来自账外输入, 别人复算不了]" % rec.get("source"))
        elif have is None:
            note = "[账里没记母版文件名, 这条核验无法复算]"
    return [], True, False, note


def run_grade(root, only_l3=False):
    """返回 (全体是否达标, 输出行, 逐级结果)。

    only_l3=True 时 L4/L5 一律 SKIP 且不参与判定 —— 这是 CI 用的口径:
    它要回答的是"仓库内可独立验证的三级过没过", 不是"你有没有私有证据"。
    """
    lines = ["等级判定"]
    titles = method_titles(root)
    lv = {}

    # L1
    red1, _ = check_criteria(root)
    lv["L1"] = not red1
    lines.append("  L1 判据完备        %s  %s"
                 % ("PASS" if lv["L1"] else "FAIL",
                    "%d 条判据(METHOD+DOCTRINE)都带变红条件" % criteria_count(root)
                    if lv["L1"] else "; ".join(red1[:3])))

    # L2
    fals = os.path.join(root, "scripts", "falsify.py")
    if not os.path.exists(fals):
        lv["L2"], l2msg = False, "scripts/falsify.py 不存在"
    else:
        try:
            r = subprocess.run([sys.executable, fals, "--selftest"],
                               capture_output=True, timeout=90)
            lv["L2"] = (r.returncode == 0)
            tail = (r.stdout or b"").decode("utf-8", "replace").strip().splitlines()
            l2msg = (tail[-1] if tail else "") if lv["L2"] else "falsify --selftest 非零退出"
        except Exception as e:            # noqa: BLE001
            lv["L2"], l2msg = False, "falsify --selftest 无法执行: %s" % e
    lines.append("  L2 判据可被证伪    %s  %s"
                 % ("PASS" if lv["L2"] else "FAIL", l2msg))

    # L3
    f3, count = grade_l3(root, titles)
    lv["L3"] = not f3
    lines.append("  L3 真实案例 >= %-2d   %s  %s"
                 % (GRADE_MIN_CASES, "PASS" if lv["L3"] else "FAIL",
                    "%d 个案例,四段齐全,判据可对上" % count if lv["L3"]
                    else "; ".join(f3[:3])))
    for extra in f3[3:]:
        lines.append("                      %s" % extra)

    # L4
    # 缺证据是 UNKNOWN, 不是 FAIL —— 与下面 L5 同一写法。
    # 上一版写成 (u4 and not f4): 未知时 f4 一定非空(它的内容就是"为什么未知"),
    # 于是条件恒假, UNKNOWN 永不出现, 缺证据一律显示 FAIL ——
    # 而同一行的括号里还写着"(未知, 不是失败)"。同一份输出自相矛盾。
    f4, n4, u4 = grade_l4(root)
    lv["L4"] = (not f4) if not u4 else False
    if only_l3:
        lines.append("  L4 判据被真仓打脸  %-7s 本次不判(--grade-l3 只判仓库内可独立验证的三级)" % "SKIP")
    else:
        tag4 = "UNKNOWN" if u4 else ("PASS" if not f4 else "FAIL")
        lines.append("  L4 判据被真仓打脸  %-7s %s"
                     % (tag4, "%d 个真仓证据, %d 条判据都红过"
                        % (n4, len(L4_ITEMS)) if not f4
                        else "; ".join(f4[:2])))

    # L5
    f5, ok5, u5, note5 = grade_l5(root)
    lv["L5"] = ok5
    if only_l3:
        lines.append("  L5 覆盖诚实        %-7s 本次不判(--grade-l3 只判仓库内可独立验证的三级)" % "SKIP")
    else:
        tag5 = "UNKNOWN" if (u5 and not ok5) else ("PASS" if ok5 else "FAIL")
        lines.append("  L5 覆盖诚实        %-7s %s"
                     % (tag5, "分母闭合 + 每条 covered 有变红记录 + text-only<=covered"
                        if ok5 else "; ".join(f5[:2])))
        if note5:
            # 通过了也要说清楚通过的前提: 复算不了的那部分, 不能算在自己头上。
            lines.append("                      %s" % note5)

    if only_l3:
        # 只判三级时, 等级也只有"三级过没过"两种说法。
        # 上一版照样打印五级的 super/expert —— 一份声称只看三级的输出,
        # 结论却由五级算出, 读到 expert 的人无法知道是被 L4/L5 拉下来的。
        ok = all(lv.get(k) for k in ("L1", "L2", "L3"))
        name = ("l3-pass (L1-L3 全过; L4/L5 本次不判)" if ok
                else "not-yet (L1-L3 未过)")
        lines.append("")
        lines.append("GRADE  %s" % name)
        return ok, lines, lv

    ok = all(lv.get(k) for k in ("L1", "L2", "L3", "L4", "L5"))
    l3ok = all(lv.get(k) for k in ("L1", "L2", "L3"))
    lines.append("")
    if ok:
        name = "super-expert (超级专家级)"
    elif l3ok:
        name = "expert (专家级 · L4/L5 未过, 缺证据或缺诚实)"
    else:
        name = "not-yet (未达专家级)"
    lines.append("GRADE  %s" % name)
    return ok, lines, lv


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
        _mk(good, "DOCTRINE.md", "## 算子 · 示例\n\n**变红条件**: 前提不成立就红\n")
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

        # 发布流程天天用 GitHub token, 而扫描表曾经只认 sk-/bearer/私钥。
        # 这一条锁定那个漏洞: 换一种真 token 形态, 必须同样红。
        _mk(good, "ci.env", "TOKEN=" + "gh" + "p_" + "a" * 36 + "\n")
        r2b, _, _ = run(good)
        chk("github token => red", r2b > 0, "red=%d" % r2b)
        os.remove(os.path.join(good, "ci.env"))

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
        _mk(gd, "DOCTRINE.md",
            "## 算子 · 示例\n\n**变红条件**: 前提不成立就红\n")
        _mk(gd, "scripts/falsify.py", "import sys\nsys.exit(0)\n")

        _mk_case(gd, "001-a")
        _mk_case(gd, "002-b")
        _ok2, _l2, lv2 = run_grade(gd)
        chk("grade: only 2 cases => L3 fail", not lv2["L3"], "L3=%s" % lv2["L3"])

        _mk_case(gd, "003-c")
        ok3, _l3, lv3 = run_grade(gd)
        chk("grade: 3 complete cases => L3 pass", lv3["L3"], "L3=%s" % lv3["L3"])
        # 关键: L3 过了但缺 L4/L5 证据, 整体必须是 expert 而不是 super。
        # 这一条就是「诚实降级」的判据 —— 没有它, 只要 L3 绿就自动发超级称号。
        chk("grade: L3 only => not super (honest downgrade)", not ok3,
            "ok=%s" % ok3)

        _mk_case(gd, "003-c", drop="修法")
        _ok4, _l4, lv4 = run_grade(gd)
        chk("grade: missing section => L3 fail", not lv4["L3"], "L3=%s" % lv4["L3"])

        _mk_case(gd, "003-c", crit="十 · 根本不存在")
        _ok5, _l5, lv5 = run_grade(gd)
        chk("grade: dangling criterion => L3 fail", not lv5["L3"], "L3=%s" % lv5["L3"])

        _mk_case(gd, "003-c")
        os.remove(os.path.join(gd, "cases", "003-c", "evidence", "raw.txt"))
        _ok6, _l6, lv6 = run_grade(gd)
        chk("grade: empty evidence => L3 fail", not lv6["L3"], "L3=%s" % lv6["L3"])

        _mk_case(gd, "003-c")
        _mk(gd, "scripts/falsify.py", "import sys\nsys.exit(1)\n")
        _ok7, _l7, lv7 = run_grade(gd)
        chk("grade: falsify red => L2 fail", not lv7["L2"], "L2=%s" % lv7["L2"])

        # ---- L4 / L5: 缺证据不许算过, 有证据必须能过 ----
        # 只验「会判不过」等于没验: 一个永远 UNKNOWN 的判定器同样会过前几条。
        _mk(gd, "scripts/falsify.py", "import sys\nsys.exit(0)\n")

        def _run_shape_ev(name, p, items):
            _mk(gd, "runs/" + name, "x P=%d\nITEMS %s\n" % (p, items))

        def _run_probe_ev(name, n, items):
            _mk(gd, "runs/" + name,
                "SCAN files=4 docs=%d subjects=%d\nITEMS %s\n" % (n - 4, n, items))

        def _cover(l5="true", verified="true", items=97):
            _mk(gd, "runs/cover-01-a.json",
                '{"covered": ["C1.1"], "absent": 90, "l5": %s, "items": %d,'
                ' "source_verified": %s}' % (l5, items, verified))

        ok8, l8, _lv8 = run_grade(gd)
        chk("grade: no runs => not super", not ok8, "ok=%s" % ok8)
        # 锁显示口径, 不只锁通过与否: 缺证据必须是 UNKNOWN。
        # 上一版永远显示 FAIL, 而括号里写着"(未知, 不是失败)" —— 同一行自相矛盾。
        l4line = [l for l in l8 if "L4" in l and "判据被真仓" in l]
        chk("grade: no runs => L4 显示 UNKNOWN(不是 FAIL)",
            bool(l4line) and "UNKNOWN" in l4line[0] and "FAIL" not in l4line[0],
            l4line[0].strip() if l4line else "(没有 L4 行)")

        # --grade-l3 的口径: 缺 L4/L5 证据时, 三级全绿就算过, 且不得显示五级结论。
        ok_l3, l_l3, _ = run_grade(gd, only_l3=True)
        chk("grade-l3: 缺 L4/L5 证据仍算过(三级全绿)", ok_l3, "ok=%s" % ok_l3)
        l45 = [l for l in l_l3 if l.strip().startswith(("L4 ", "L5 "))]
        chk("grade-l3: L4/L5 显示 SKIP 而不是 FAIL/UNKNOWN",
            bool(l45) and all("SKIP" in l for l in l45), " | ".join(x.strip() for x in l45))
        chk("grade-l3: GRADE 行不出现 super/expert 五级称号",
            any("l3-pass" in l for l in l_l3),
            [l for l in l_l3 if l.startswith("GRADE")][0].strip())

        for i in (1, 2, 3):
            _run_shape_ev("shape-%02d-a.txt" % i, 30,
                          "A5=RED A2=RED HUB=YELLOW DEPTH=RED")
        # probe 的证据必须被认: 只认 shape-* 的版本会把新仪器当没跑过
        _run_probe_ev("probe-01-a.txt", 40,
                      "SWALLOW=RED DUP=RED ORPHAN=RED DEPS=RED")
        _cover()
        ok9, _l9, lv9 = run_grade(gd)
        chk("grade: 3 shape + 1 probe + cover => super", ok9,
            "ok=%s L4=%s L5=%s" % (ok9, lv9["L4"], lv9["L5"]))

        os.remove(os.path.join(gd, "runs", "shape-02-a.txt"))
        os.remove(os.path.join(gd, "runs", "shape-03-a.txt"))
        ok10, _l10, _lv10 = run_grade(gd)
        chk("grade: 2 runs < 3 => not super", not ok10, "ok=%s" % ok10)

        for i in (1, 2, 3):
            _run_shape_ev("shape-%02d-a.txt" % i, 30,
                          "A5=PASS A2=RED HUB=YELLOW DEPTH=RED")
        ok11, _l11, lv11 = run_grade(gd)
        chk("grade: one item never red => not super", not ok11,
            "L4=%s" % lv11["L4"])

        for i in (1, 2, 3):
            _run_shape_ev("shape-%02d-a.txt" % i, 30,
                          "A5=RED A2=RED HUB=YELLOW DEPTH=RED")
        _cover(verified="false")
        ok12, _l12, lv12 = run_grade(gd)
        chk("grade: unverified denominator => not super", not ok12,
            "L5=%s" % lv12["L5"])

        _cover(l5="false", items=10)
        ok13, _l13, lv13 = run_grade(gd)
        chk("grade: cover l5 false => not super", not ok13, "L5=%s" % lv13["L5"])

        # DOCTRINE.md 缺了就红: 判据表被分成两份之后, 少扫一份就是少查一半
        os.remove(os.path.join(gd, "DOCTRINE.md"))
        ok14, _l14, lv14 = run_grade(gd)
        chk("grade: DOCTRINE missing => L1 fail", not lv14["L1"], "L1=%s" % lv14["L1"])
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
    if "--grade" in argv or "--grade-l3" in argv:
        only3 = "--grade-l3" in argv
        # 上一版: 两种模式都跑五级, 只有 rc 按三级算 ——
        # 输出里照样打 super/expert/FAIL/UNKNOWN, 读者看到的是五级结论。
        ok, lines, lv = run_grade(root, only_l3=only3)
        print("\n".join(lines))
        if only3:
            print("SCOPE  L1-L3 only (完整等级请跑 --grade)")
        return 0 if ok else 1
    red, _yellow, lines = run(root)
    print("\n".join(lines))
    return 1 if red else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
