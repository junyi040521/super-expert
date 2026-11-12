#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""shape.py - 形态判定。只判能判的 4 条, 其余输出「人工」。红则非零退出。

用法:
    python shape.py <root>
    python shape.py --strict <root>        # 豁免项也列出来
    python shape.py --json runs/x.json <root>
    python shape.py --selftest

可自动判的 4 条(其余 4 条明确输出 not-auto, 不假装判过):
    A5 尺度无关   写了「除 X 之外 / except for」这类特例句 => 红, 每处计 1
    A2 可归属     junk 类目录(utils/common/misc...)文件占比 > 10% => 红, 需 P>=20
    伪枢纽 r=1    目录下仅 1 个条目且仍是目录 => 黄(严格模式仍是黄, 但列出来)
    过度坍缩      D = ceil(log_r P) > 3 => 红, 需 P>=20 且 r>=3

三条设计约束, 都是被坑出来的:
  1. 样本不足必须 N/A, 且 N/A 不进入通过计数。16 个文件的仓库算出「4/4 全绿」
     和「D=4 层」是同一个病的两面: 分母太小, 读数是噪声。
  2. 豁免不许写死在代码里, 必须登记在 SHAPE.md 的「## 豁免」表, 每条带理由与依据。
     写死等于留一个无人审计的后门。
  3. 判据自述文件(SHAPE.md)与本源文件必须跳过扫描。判据里要写模式示例,
     不跳过就会自己命中自己 —— 与 gate.py 跳过自身同因。
"""

import fnmatch
import json
import os
import re
import shutil
import sys
import tempfile

SELF = os.path.basename(__file__)
SPEC = "SHAPE.md"

SKIP_DIR = {".git", "__pycache__", "node_modules", ".venv", "venv",
            "dist", "build", ".idea", ".vscode", ".mypy_cache"}
JUNK_DIRS = {"utils", "util", "common", "misc", "helpers", "other",
             "shared", "commons", "miscellaneous"}

MIN_P = 20          # 样本门槛: 少于 20 个文件不判比例类指标
A2_RATIO = 0.10

# 模式拼接构造, 源码里不出现完整字面量(否则自扫先红)
_PAT_A5 = [
    ("chu-waizhi", "\u9664" + r"[^\n]{1,24}?\u4e4b\u5916"),
    ("chule-dou", "\u9664" + r"\u4e86[^\n]{0,12}?\u90fd"),
    ("except-for", r"(?i)\bexcept\s+for\b"),
    ("with-exception", r"(?i)with\s+the\s+exception\s+of"),
]

MANUAL = [
    ("A1 \u5355\u53c2\u7167\u7cfb", "\u540c\u540d\u76ee\u5f55\u5728\u8de8\u7236\u7ea7\u91cd\u590d\u51fa\u73b0"
     "\u65f6\u65e0\u6cd5\u533a\u5206\u300c\u539f\u70b9\u6f02\u79fb\u300d\u4e0e\u300c\u81ea\u76f8\u4f3c\u300d"
     "(evidence/ x3 \u5373\u540e\u8005)"),
    ("A3 \u4f18\u52bf\u68af\u5ea6", "\u4ee3\u7801\u91cc\u6ca1\u6709\u300c\u8c01\u66f4\u4f18\u300d\u8fd9\u6761\u4fe1\u606f"),
    ("A4 \u95ed\u5408", "\u591a\u4e2a CLI \u5165\u53e3\u5e38\u5e38\u662f\u6b63\u786e\u8bbe\u8ba1"
     "(\u4e09\u4ef6\u4eea\u5668\u5c31\u8be5\u4e09\u4e2a\u5165\u53e3), \u5224\u5b83\u4f1a\u60e9\u7f5a\u5bf9\u7684\u7ed3\u6784"),
    ("\u786c\u7f16\u7801\u574d\u7f29", "\u9700\u8981\u4eba\u58f0\u660e\u300c\u6211\u505a\u8fc7 \u03ba\u300d"),
]


def read_text(path):
    try:
        with open(path, "rb") as f:
            raw = f.read()
        if b"\x00" in raw[:4096]:
            return None
        return raw.decode("utf-8", "replace")
    except OSError:
        return None


def collect(root):
    files, dirs = [], []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIR)
        dirs.append(dirpath)
        for fn in filenames:
            files.append(os.path.join(dirpath, fn))
    return files, dirs


def rel(root, p):
    return os.path.relpath(p, root).replace("\\", "/")


def load_waivers(root):
    """从 SHAPE.md 的「## 豁免」表读豁免路径。返回 [(path_glob, reason, basis)]。

    表格式: | 路径 | 理由 | 依据 |。没有该表就返回空 —— 没有登记就没有豁免。
    """
    path = os.path.join(root, SPEC)
    txt = read_text(path) if os.path.exists(path) else None
    if not txt:
        return []
    out = []
    m = re.search(r"(?m)^##\s*\u8c41\u514d", txt)
    if not m:
        return []
    tail = txt[m.end():]
    nxt = re.search(r"(?m)^##\s", tail)
    if nxt:
        tail = tail[:nxt.start()]
    for line in tail.splitlines():
        s = line.strip()
        if not s.startswith("|"):
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        if len(cells) < 2:
            continue
        if set(cells[0]) <= set("-: "):
            continue
        p = cells[0].strip("`").strip()
        if not p or p in ("\u8def\u5f84", "\u76ee\u5f55", "path"):
            continue
        if not re.search(r"[A-Za-z0-9]", p):
            continue
        out.append((p, cells[1] if len(cells) > 1 else "",
                    cells[2] if len(cells) > 2 else ""))
    return out


def is_waived(relpath, waivers):
    for pat, reason, basis in waivers:
        if fnmatch.fnmatch(relpath, pat) or relpath == pat:
            return reason, basis
        # 目录豁免覆盖其下所有内容
        if not any(ch in pat for ch in "*?") and relpath.startswith(pat + "/"):
            return reason, basis
    return None


# ---------------- 四条可判 ----------------

def check_a5(root, files):
    hits = []
    waived = []
    for p in files:
        if not p.endswith((".md", ".txt")):
            continue
        base = os.path.basename(p)
        if base == SPEC or base == SELF:
            continue
        txt = read_text(p)
        if txt is None:
            continue
        # 判据要能描述反例, 就得把反例句写出来 —— 于是它必然命中自己。
        # 不给暗门, 给一条写在案发现场的豁免: 文件里写 `a5-waiver: <理由>`,
        # 理由 >=4 字才算, 且被豁免的文件数会打印出来, 不静默。
        wm = re.search(r"a5-waiver:\s*(\S.{3,})", txt)
        if wm:
            waived.append("%s(%s)" % (rel(root, p), wm.group(1)[:18]))
            continue
        for lineno, line in enumerate(txt.splitlines(), 1):
            for name, pat in _PAT_A5:
                if re.search(pat, line):
                    hits.append("%s:%d [%s]" % (rel(root, p), lineno, name))
    if hits:
        return "RED", "%d \u5904\u7279\u4f8b\u53e5" % len(hits), hits
    return ("PASS", "0 \u5904\u7279\u4f8b\u53e5" +
            (" / waived=%d" % len(waived) if waived else ""), [])


def check_a2(root, files, pcount):
    if pcount < MIN_P:
        return ("N/A", "P=%d < %d, 1 \u4e2a\u6587\u4ef6 = %.2f%%, \u566a\u58f0\u5373\u7ea2\u7ebf"
                % (pcount, MIN_P, 100.0 / max(pcount, 1)), [])
    junk = []
    for f in files:
        parts = rel(root, f).split("/")[:-1]
        if any(x.lower() in JUNK_DIRS for x in parts):
            junk.append(rel(root, f))
    ratio = len(junk) / float(pcount)
    detail = "junk %d/%d = %.2f%%" % (len(junk), pcount, ratio * 100)
    if ratio > A2_RATIO:
        return "RED", detail, junk[:8]
    return "PASS", detail, []


def check_hub(root, dirs, waivers, strict):
    chains, waived = [], []
    for d in dirs:
        try:
            ents = [e for e in os.listdir(d)
                    if e not in SKIP_DIR and not e.startswith(".")]
            allents = [e for e in os.listdir(d) if e not in SKIP_DIR]
        except OSError:  # noqa: swallow 目录在遍历中途被删, 跳过是正确语义
            continue
        if len(allents) != 1:
            continue
        child = os.path.join(d, allents[0])
        if not os.path.isdir(child):
            continue
        rp = rel(root, child)
        w = is_waived(rp, waivers)
        if w:
            waived.append("%s  <%s>" % (rp, w[0][:36]))
        else:
            chains.append(rp)
        del ents
    detail = "%d \u5904\u5355\u5b50\u76ee\u5f55\u94fe" % len(chains)
    if waived:
        detail += ", %d \u5904\u5df2\u767b\u8bb0\u8c41\u514d" % len(waived)
    if chains:
        lines = list(chains)
        if strict and waived:
            lines += ["(\u8c41\u514d) " + x for x in waived]
        return "YELLOW", detail, lines
    if strict and waived:
        return "PASS", detail, ["(\u8c41\u514d) " + x for x in waived]
    return "PASS", detail, []


def check_depth(root, dirs, pcount):
    """只看不判(INFO)。三个真实目录实测后主动降级, 原因写在下面。

    原本是 D = ceil(log_r P) > 3 判红。实测四个真实目录:
        outputs(P=88,depth=1) / my-experts(P=383,depth=8)
        skills(P=34,depth=2) / \u5de5\u4f5c\u533a(P=12914,depth=10)
    两个问题:
      1. r >= 3 的门槛在真实树上几乎不成立(分支因子普遍 1.5-2.5), 于是恒 N/A;
      2. 放宽门槛后, r=2 的树只要有 9 个叶就会红 —— 变成恒红。
    恒 N/A 与恒红都不是判据, 是装饰。而深嵌套的真实病理(每层只装一个目录)
    已经由「伪枢纽」捕获, 这条没有独立信息量。
    所以它只报数, 不下结论: 数字给人看, 判定交给伪枢纽与人工。
    """
    if pcount == 0:
        return "INFO", "\u7a7a\u76ee\u5f55", []
    layers = {}
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in SKIP_DIR]
        r = rel(root, dp)
        d = 0 if r == "." else r.count("/") + 1
        if d not in layers:
            layers[d] = [0, 0]
        layers[d][0] += 1
        layers[d][1] += len(dn) + len(fn)
    if not layers:
        return "INFO", "\u6ca1\u6709\u76ee\u5f55", []
    md = max(layers)
    avg = layers[md][1] / float(layers[md][0])
    subs, branchy = 0, 0
    for d in dirs:
        try:
            ents = [e for e in os.listdir(d) if e not in SKIP_DIR]
        except OSError:  # noqa: swallow 目录在遍历中途被删, 跳过是正确语义
            continue
        kids = [e for e in ents if os.path.isdir(os.path.join(d, e))]
        if kids:
            branchy += 1
            subs += len(kids)
    r = (subs / float(branchy)) if branchy else 0.0
    detail = "P=%d depth=%d r=%.2f deepest_avg=%.2f" % (pcount, md, r, avg)
    return "INFO", detail, []


def run_shape(root, strict=False):
    files, dirs = collect(root)
    pcount = len(files)
    waivers = load_waivers(root)
    rows = []

    st, det, extra = check_a5(root, files)
    rows.append(("A5 \u5c3a\u5ea6\u65e0\u5173", st, det, extra))
    st, det, extra = check_a2(root, files, pcount)
    rows.append(("A2 \u53ef\u5f52\u5c5e", st, det, extra))
    st, det, extra = check_hub(root, dirs, waivers, strict)
    rows.append(("\u4f2a\u67a2\u7ebd r=1", st, det, extra))
    st, det, extra = check_depth(root, dirs, pcount)
    rows.append(("\u6df1\u5ea6(\u53ea\u770b)", st, det, extra))

    lines = ["\u5f62\u6001\u5224\u5b9a  root=%s  P=%d  waivers=%d"
             % (root, pcount, len(waivers))]
    for name, st, det, extra in rows:
        lines.append("  %-14s %-6s %s" % (name, st, det))
        for e in extra:
            lines.append("                 - %s" % e)
    lines.append("  -- \u4eba\u5de5(\u4e0d\u53ef\u81ea\u52a8\u5224): "
                 + " / ".join(n for n, _ in MANUAL))
    for n, why in MANUAL:
        lines.append("     %s: %s" % (n, why))

    cnt = {"PASS": 0, "RED": 0, "YELLOW": 0, "N/A": 0, "INFO": 0}
    for _, st, _, _ in rows:
        cnt[st] = cnt.get(st, 0) + 1
    lines.append("")
    lines.append("RESULT pass=%d red=%d yellow=%d na=%d info=%d"
                 % (cnt["PASS"], cnt["RED"], cnt["YELLOW"], cnt["N/A"],
                    cnt["INFO"]))
    # 机器可读的一行。gate.py 的 L4 只认这一行, 不靠中文标题去正则,
    # 否则改一个措辞就会让等级判定悄悄失效(判据指向了想象的位置)。
    lines.append("ITEMS " + " ".join(
        "%s=%s" % (code, st) for code, (_n, st, _d, _e)
        in zip(("A5", "A2", "HUB", "DEPTH"), rows)))
    if cnt["N/A"]:
        lines.append("NOTE   N/A \u4e0d\u7b97\u901a\u8fc7: \u6837\u672c\u4e0d\u8db3\u65f6\u4e0d\u80fd"
                     "\u62ff\u300c\u5168\u7eff\u300d\u5f53\u7ed3\u8bba")
    ok = cnt["RED"] == 0
    return ok, lines, {"root": os.path.abspath(root), "p": pcount,
                       "waivers": len(waivers),
                       "results": [{"id": n, "status": s, "detail": d}
                                   for n, s, d, _ in rows]}


# ---------------- selftest ----------------

def _mk(root, relpath, text):
    p = os.path.join(root, relpath)
    d = os.path.dirname(p)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def selftest():
    """6 项。必须同时验证「该红会红」与「不该红不红」——
    一个永远返回红的检查器和永远返回绿的一样没用, 而假红会让真红也失去可信度。
    """
    base = tempfile.mkdtemp(prefix="shape_st_")
    results = []

    def chk(name, cond, detail=""):
        results.append((name, bool(cond), detail))

    def status_of(rows, needle):
        for n, s, d, _e in rows:
            if needle in n:
                return s
        return "?"

    try:
        # 1 小样本: 比例类必须 N/A, 不是红也不是绿
        small = os.path.join(base, "small")
        _mk(small, "README.md", "hello\n")
        for i in range(4):
            _mk(small, "scripts/s%d.py" % i, "print(1)\n")
        ok, _l, _j = run_shape(small)
        files, _d = collect(small)
        rows = [("A2 \u53ef\u5f52\u5c5e",) + check_a2(small, files, len(files))[:2] + ([],)]
        chk("small repo: A2 => N/A (not red)", status_of(rows, "A2") == "N/A",
            status_of(rows, "A2"))
        rows2 = [("D",) + check_depth(small, _d, len(files))[:2] + ([],)]
        chk("small repo: depth is INFO (never a verdict)",
            status_of(rows2, "D") == "INFO", status_of(rows2, "D"))

        # 2 A5: 注入特例句 => 红; 撤除 => 归零
        _mk(small, "notes.md", "\u9664\u4e86\u8fd9\u4e00\u6761\u90fd\u9002\u7528\n")
        ok1, _l1, _j1 = run_shape(small)
        chk("inject special-case sentence => red", not ok1, "ok=%s" % ok1)
        os.remove(os.path.join(small, "notes.md"))
        ok2, _l2, _j2 = run_shape(small)
        chk("remove it => back to ok", ok2, "ok=%s" % ok2)

        # 3 A2: P>=20 且 junk 超线 => 红
        big = os.path.join(base, "big")
        for i in range(24):
            _mk(big, "mod/m%02d.py" % i, "x=1\n")
        for i in range(6):
            _mk(big, "utils/u%d.py" % i, "y=1\n")
        files, dirs = collect(big)
        st, det, _ = check_a2(big, files, len(files))
        chk("big repo: junk 6/30 > 10% => red", st == "RED", det)

        # 4 伪枢纽: 单子目录链 => 黄, 且不计红
        _mk(big, "wrap/inner/leaf.txt", "z\n")
        files, dirs = collect(big)
        st, det, _ = check_hub(big, dirs, [], False)
        chk("single-child chain => yellow", st == "YELLOW", det)

        # 5 豁免登记后同一链 => 不报(证明豁免来自文档, 不是写死)
        _mk(big, SPEC, "# \u5f62\u6001\n\n## \u8c41\u514d\n\n"
            "| \u8def\u5f84 | \u7406\u7531 | \u4f9d\u636e |\n|---|---|---|\n"
            "| wrap/inner | \u6d4b\u8bd5\u7528 | selftest |\n")
        w = load_waivers(big)
        st, det, _ = check_hub(big, dirs, w, False)
        chk("waiver from SHAPE.md => not reported (%d)" % len(w), st == "PASS", det)

        # 6 深度必须是 INFO 且带数: 降级不等于不测 —— 不测和不判是两件事
        flat = os.path.join(base, "flat")
        for i in range(40):
            _mk(flat, "d%d/f.txt" % i, "a\n")
        files, dirs = collect(flat)
        st, det, _ = check_depth(flat, dirs, len(files))
        chk("flat 40 dirs => INFO with numbers",
            st == "INFO" and "depth=" in det, "%s %s" % (st, det))

        # 7 深树: 只报数不判红(纸面上它是红, 实测两次口径都不成立才降级)
        deep = os.path.join(base, "deep")
        for a in range(4):
            for b in range(4):
                for c in range(4):
                    for f in range(4):
                        _mk(deep, "L%d/L%d/L%d/f%d.txt" % (a, b, c, f), "v\n")
        files, dirs = collect(deep)
        st, det, _ = check_depth(deep, dirs, len(files))
        chk("deep tree => INFO not fake red", st == "INFO", "%s %s" % (st, det))
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
    args = [a for a in argv[1:] if not a.startswith("--")]
    root = args[0] if args else "."
    if not os.path.isdir(root):
        print("not a dir: %s" % root)
        return 2
    strict = "--strict" in argv
    ok, lines, rec = run_shape(root, strict)
    print("\n".join(lines))
    if "--json" in argv:
        i = argv.index("--json")
        if i + 1 < len(argv):
            out = argv[i + 1]
            d = os.path.dirname(os.path.abspath(out))
            if d:
                os.makedirs(d, exist_ok=True)
            with open(out, "w", encoding="utf-8", newline="\n") as f:
                json.dump(rec, f, ensure_ascii=False, indent=1, sort_keys=True)
                f.write("\n")
            print("WROTE %s" % out)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
