#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cover.py - 覆盖账。声明 covered 就得指向真实存在、且真的红过的判据。

用法:
    python cover.py <root>                                  # 只能判账本自身
    python cover.py --source <capability-inventory.md> <root>
    python cover.py --selftest

三种状态:
    covered    有判据, 判据指向的代码真实存在, 且 runs/ 里有它的变红记录
    text-only  只在文档里主张, 没有可执行判据
    absent     未被覆盖(在域表里按算术体现, 不逐条列出)

L5 三条(全部机械可判):
    1 分母闭合    31 个域、每域 covered + text-only + absent == 项数;
                  --source 提供时, 分母必须与母版条目数一致(防分母漂移)
    2 有红的出路  每条 covered 的判据在 runs/ 里有一条 `FIRE <判据指向>`,
                  且同一份证据里能看到非 PASS 的输出
    3 账不虚胖    text-only 不得超过 covered

旧版 L5 是 `absent >= 3 x covered`。已废弃, 原因是它会惩罚诚实:
覆盖从 6 项做到 12 项时, 这条反而判红。一个「越诚实越红」的判据
与「从不否决的闸门」是同一族缺陷, 只是方向相反。诚实的轴不是比例,
是「每一条声明都有一次真实的红」。

两条不可省的约束:
  1. 分母有两个来源: 本表合计行(账内残差)与 --source 实测。
     读不到母版时仍能算出 absent, 但必须标 `分母未核验`——
     「账内残差」与「实测未覆盖」是两件事, 混起来就成了自证。
  2. 合计行必须与实测条目数一致。账本自己对不上, 是最容易自欺的一种。
"""

import json
import os
import re
import shutil
import sys
import tempfile

MAP = "MAP.md"
DOMAIN_RE = re.compile(r"^(D\d+)\b")
ID_RE = re.compile(r"^(C\d+\.\d+)$")
ITEM_RE = re.compile(r"(?m)^###\s+(C\d+\.\d+)")
TOTAL_RE = re.compile(
    r"<!--\s*cover-total\s+items=(\d+)\s+domains=(\d+)\s+covered=(\d+)\s+text-only=(\d+)\s*-->")
FIRE_RE = re.compile(r"(?m)^FIRE\s+(\S+::\S+)\s*$")
# 非 PASS 的形态不止一种: 闸门的 RED、自测的 FAIL、等级的 not-yet、
# 打包复核的 bytes_match=False。只认 RED 会把真实证据判成"全绿"。
NONPASS_RE = re.compile(
    r"(?m)^(?:RED|FAIL|YELLOW)\b"
    r"|^RESULT .*(?:red=[1-9]|FAIL|not-yet|MISMATCH)"
    r"|_match=False\b")


def read_text(path):
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError:
        return None
    if b"\x00" in raw[:4096]:
        return None
    return raw.decode("utf-8", "replace")


def _cells(line):
    return [c.strip() for c in line.strip().strip("|").split("|")]


def _ids(cell):
    if cell.strip("` ").strip() in ("-", "--", "—", ""):
        return []
    out = []
    for part in re.split(r"[,，\s]+", cell):
        p = part.strip("` ")
        if ID_RE.match(p):
            out.append(p)
    return out


def parse_map(root):
    """返回 (domains, items, total, fails, yellows)。

    domains: {D1: {items, covered[], text_only[], absent}}
    items:   {C1.1: {name, ref, kind}}
    """
    path = os.path.join(root, MAP)
    if not os.path.exists(path):
        return {}, {}, None, ["%s 缺失: 没有覆盖声明, 覆盖账无从谈起" % MAP], []
    txt = read_text(path) or ""
    doms, items, fails, yellows = {}, {}, [], []
    for line in txt.splitlines():
        s = line.strip()
        if not s.startswith("|"):
            continue
        cells = _cells(s)
        if len(cells) < 4:
            continue
        head = cells[0].strip("` ").strip()
        dm = DOMAIN_RE.match(head)
        if dm:
            dkey = dm.group(1)
            if len(cells) < 5:
                fails.append("%s: 域行至少 5 列(域/项数/covered/text-only/缺席)" % dkey)
                continue
            try:
                n = int(cells[1])
                absent = int(cells[4])
            except ValueError:
                fails.append("%s: 项数或缺席数不是整数(%r/%r)" % (dkey, cells[1], cells[4]))
                continue
            cov, txtonly = _ids(cells[2]), _ids(cells[3])
            doms[dkey] = {"items": n, "covered": cov, "text_only": txtonly,
                          "absent": absent}
        elif ID_RE.match(head):
            kind = cells[3].strip("` ").strip().lower()
            if kind not in ("covered", "text-only"):
                fails.append("%s: 类型只能是 covered / text-only, 读到 %r" % (head, kind))
                continue
            items[head] = {"name": cells[1], "ref": cells[2], "kind": kind}
    if not doms:
        fails.append("%s 里没有任何 D<编号> 域行" % MAP)
    if not items:
        fails.append("%s 里没有任何 C<域>.<项> 条目行" % MAP)
    m = TOTAL_RE.search(txt)
    total = None
    if m:
        total = {"items": int(m.group(1)), "domains": int(m.group(2)),
                 "covered": int(m.group(3)), "text_only": int(m.group(4))}
    else:
        fails.append("%s 缺合计行 <!-- cover-total items=N domains=N covered=N text-only=N -->"
                     % MAP)
    return doms, items, total, fails, yellows


def check_ref(root, ref):
    """一条判据指向。支持 a.py,b.py 与 path::TOKEN。返回失败列表。"""
    fails = []
    parts = [x.strip() for x in ref.split(",") if x.strip()]
    if not parts:
        return ["判据指向为空"]
    for one in parts:
        if "::" in one:
            pth, token = one.split("::", 1)
        else:
            pth, token = one, None
        pth = pth.strip("` ")
        target = os.path.join(root, pth.replace("/", os.sep))
        if not os.path.exists(target):
            fails.append("路径不存在: %s" % pth)
            continue
        if token:
            txt = read_text(target)
            if txt is None or token.strip() not in txt:
                fails.append("%s 里没有标记 %r" % (pth, token.strip()))
    return fails


def check_selftest(root, ref):
    miss = []
    for one in [x.strip() for x in ref.split(",") if x.strip()]:
        pth = one.split("::", 1)[0].strip("` ")
        if not pth.endswith(".py"):
            continue
        txt = read_text(os.path.join(root, pth.replace("/", os.sep)))
        if txt and "selftest" not in txt:
            miss.append(pth)
    return miss


def fire_index(root):
    """runs/*.txt 里的变红记录。返回 ({ref: 文件名}, [证据弱到只有 FIRE 行的文件])。"""
    d = os.path.join(root, "runs")
    idx, weak = {}, []
    if not os.path.isdir(d):
        return idx, weak
    for fn in sorted(os.listdir(d)):
        if not fn.endswith(".txt"):
            continue
        txt = read_text(os.path.join(d, fn)) or ""
        fires = FIRE_RE.findall(txt)
        if not fires:
            continue
        if not NONPASS_RE.search(txt):
            weak.append(fn)
            continue
        for r in fires:
            idx.setdefault(r.strip("`"), fn)
    return idx, weak


def count_source(src):
    """母版条目数。读不到返回 None(=> unknown), 不返回 0。"""
    if not src or not os.path.exists(src):
        return None
    txt = read_text(src)
    if not txt:
        return None
    ids = ITEM_RE.findall(txt)
    return len(ids) if ids else None


def run_cover(root, source=None):
    doms, items, total, reds, yellows = parse_map(root)
    fires, weak = fire_index(root)
    for fn in weak:
        yellows.append("runs/%s: 有 FIRE 行但没有非 PASS 输出, 证据不计" % fn)

    covered_ids, textonly_ids = [], []
    for cid, it in sorted(items.items()):
        if it["kind"] == "covered":
            f = check_ref(root, it["ref"])
            if f:
                for x in f:
                    reds.append("%s %s: %s" % (cid, it["name"][:12], x))
                continue
            st = check_selftest(root, it["ref"])
            if st:
                yellows.append("%s %s: 无 selftest (%s)"
                               % (cid, it["name"][:12], ",".join(st)))
            if it["ref"].strip() not in fires:
                reds.append("%s: covered 但 runs/ 里没有 FIRE %s —— 没红过的判据不算判据"
                            % (cid, it["ref"].strip()))
            covered_ids.append(cid)
        else:
            textonly_ids.append(cid)

    # 域表与条目表必须互相对得上(两边都写一遍, 就必然有一天对不上)
    dom_cov, dom_txt = {}, {}
    for dname, d in doms.items():
        dom_cov[dname] = d["covered"]
        dom_txt[dname] = d["text_only"]
        calc = len(d["covered"]) + len(d["text_only"]) + d["absent"]
        if calc != d["items"]:
            reds.append("%s: covered(%d)+text-only(%d)+absent(%d)=%d != 项数 %d"
                        % (dname, len(d["covered"]), len(d["text_only"]),
                           d["absent"], calc, d["items"]))
    missing = [c for c in covered_ids
               if c not in [x for v in dom_cov.values() for x in v]]
    for c in missing:
        reds.append("%s: 条目表声明 covered, 域表里没有列出" % c)
    for dname, lst in dom_cov.items():
        for c in lst:
            if c not in items:
                reds.append("%s: 域表列了 %s, 条目表里没有这一条" % (dname, c))
            elif items[c]["kind"] != "covered":
                reds.append("%s: 域表当 covered 计, 条目表写的是 %s" % (c, items[c]["kind"]))
    for dname, lst in dom_txt.items():
        for c in lst:
            if c not in items:
                reds.append("%s: 域表列了 %s, 条目表里没有这一条" % (dname, c))
            elif items[c]["kind"] != "text-only":
                reds.append("%s: 域表当 text-only 计, 条目表写的是 %s" % (c, items[c]["kind"]))

    n_cov, n_txt = len(covered_ids), len(textonly_ids)
    n_items = sum(d["items"] for d in doms.values())
    n_src = count_source(source)
    # 母版是否随仓库发布: 只记事实, 不参与判定。
    # 它是给读账的人用的 —— "核验过"和"你能自己核验"是两件事。
    src_present = None
    if source:
        want = os.path.basename(source)
        src_present = any(want in fns for _dp, _dn, fns in os.walk(root))
    absent = None

    if total is not None:
        if total["items"] != n_items:
            reds.append("合计行 items=%d 与域表项数之和 %d 不符" % (total["items"], n_items))
        if total["domains"] != len(doms):
            reds.append("合计行 domains=%d 与实测域数 %d 不符" % (total["domains"], len(doms)))
        if total["covered"] != n_cov:
            reds.append("合计行 covered=%d 与实测 %d 条不符" % (total["covered"], n_cov))
        if total["text_only"] != n_txt:
            reds.append("合计行 text-only=%d 与实测 %d 条不符"
                        % (total["text_only"], n_txt))
        if n_src is not None and total["items"] != n_src:
            reds.append("分母漂移: 表里写 %d 项, 母版实测 %d 项" % (total["items"], n_src))
        absent = total["items"] - n_cov - n_txt

    lines = ["覆盖账  root=%s" % root]
    if n_src is None:
        lines.append("  母版条目      UNVERIFIED  分母取自本表合计行, 未经母版核验")
    else:
        lines.append("  母版条目      %d (实测)" % n_src)
    lines.append("  域            %d  项数之和 %d" % (len(doms), n_items))
    lines.append("  covered       %d  %s" % (n_cov, ",".join(covered_ids) or "-"))
    lines.append("  text-only     %d  %s" % (n_txt, ",".join(textonly_ids) or "-"))
    lines.append("  absent        %s%s" % ("UNKNOWN" if absent is None else absent,
                                          "" if absent is None else " (账内残差)"))
    lines.append("  变红记录      %d 份证据 / %d 个判据点"
                 % (len(set(fires.values())), len(fires)))
    for r in reds:
        lines.append("RED    %s" % r)
    for y in yellows:
        lines.append("YELLOW %s" % y)

    l5 = None
    if n_items == 0 or not doms:
        # 分母为 0 时任何比例都成立, 这正是"扫 0 个文件仍报通过"的同族陷阱。
        lines.append("L5     FAIL     域表为空: 分母为 0, 不算闭合")
        l5 = False
    elif absent is None:
        lines.append("L5     UNKNOWN  分母未取到, 不判")
    elif absent < 0:
        lines.append("L5     FAIL     absent 为负: 声明数超过母版条目数")
        l5 = False
    elif n_txt > n_cov:
        lines.append("L5     FAIL     text-only(%d) > covered(%d): 账面主张多于真判据"
                     % (n_txt, n_cov))
        l5 = False
    else:
        l5 = True
        lines.append("L5     PASS     分母闭合 %d 项 / %d 域, %d 条 covered 各有变红记录, "
                     "text-only %d <= %d%s"
                     % (n_items, len(doms), n_cov, n_txt, n_cov,
                        "" if n_src is not None else " (分母未核验)"))

    ok = (not reds) and (l5 is not False)
    lines.append("")
    lines.append("RESULT red=%d yellow=%d l5=%s"
                 % (len(reds), len(yellows),
                    "unknown" if l5 is None else ("pass" if l5 else "fail")))
    return ok, lines, {"covered": covered_ids, "text_only": textonly_ids,
                       "absent": absent, "items": total["items"] if total else None,
                       "domains": len(doms), "covered_n": n_cov,
                       "text_only_n": n_txt, "fire": len(fires), "l5": l5,
                       "source_verified": n_src is not None,
                       # 光有 source_verified 不够: 它只说明"传了 --source"。
                       # 母版有没有跟着仓库发出来, 决定这条核验别人能不能复算。
                       "source": os.path.basename(source) if source else None,
                       "source_present": src_present,
                       "red": len(reds), "yellow": len(yellows)}


# ---------------- selftest ----------------

def _mk(root, relpath, text):
    p = os.path.join(root, relpath)
    d = os.path.dirname(p)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def _src_file(tmp, n=10):
    body = []
    for i in range(1, n + 1):
        body.append("### C1.%d 能力%d\n\n**能力**：x\n\n**变红条件**：y\n" % (i, i))
    p = os.path.join(tmp, "cap.md")
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write("# cap\n\n" + "\n".join(body))
    return p


HEAD = ("# M\n\n| 域 | 项数 | covered | text-only | 缺席 |\n|---|---|---|---|---|\n")
HEAD2 = ("\n| 编号 | 名称 | 判据 | 类型 |\n|---|---|---|---|\n")


def _map(root, dom_rows, item_rows, total):
    body = "".join("| %s | %d | %s | %s | %d |\n" % r for r in dom_rows)
    body2 = "".join("| %s | n%s | %s | %s |\n" % (r[0], r[0], r[1], r[2])
                    for r in item_rows)
    tail = ("\n<!-- cover-total items=%d domains=%d covered=%d text-only=%d -->\n"
            % total)
    _mk(root, MAP, HEAD + body + HEAD2 + body2 + tail)


def selftest():
    """13 项。必须同时验「该红会红」「该黄会黄」「L5 会判虚胖」。"""
    base = tempfile.mkdtemp(prefix="cover_st_")
    results = []

    def chk(name, cond, detail=""):
        results.append((name, bool(cond), detail))

    try:
        src = _src_file(base, 10)          # 母版 10 项, 方便算分母
        repo = os.path.join(base, "repo")
        _mk(repo, "scripts/fake.py",
            "A = 1\nB = 2\n\ndef check_x(root):\n    return \"RED\"\n\ndef selftest():\n    return 0\n")
        _mk(repo, "runs/fire-01.txt",
            "# ev\nFIRE scripts/fake.py::check_x\nRESULT red=1\n")
        good_dom = [("D1", 4, "C1.1,C1.2", "-", 2), ("D2", 6, "-", "C1.3", 5)]
        good_item = [("C1.1", "scripts/fake.py::check_x", "covered"),
                     ("C1.2", "scripts/fake.py::check_x", "covered"),
                     ("C1.3", "doc.md", "text-only")]

        # 1 无 MAP.md => 红
        ok, _l, _j = run_cover(repo, src)
        chk("no MAP.md => red", not ok)

        # 2 域内算术不闭合 => 红
        _map(repo, [("D1", 4, "C1.1,C1.2", "-", 3), ("D2", 6, "-", "C1.3", 5)],
             good_item, (10, 2, 2, 1))
        ok, _l, _j = run_cover(repo, src)
        chk("domain arithmetic off => red", not ok)

        # 3 covered 但 runs/ 里没有 FIRE => 红(这条是 L5 的实质)
        _mk(repo, "runs/fire-01.txt", "# ev\nFIRE scripts/other.py::y\nRESULT red=1\n")
        _map(repo, good_dom, good_item, (10, 2, 2, 1))
        ok, _l, j = run_cover(repo, src)
        chk("covered without FIRE => red", not ok and j["red"] > 0)

        # 4 FIRE 行在但正文全绿 => 黄, 且不算覆盖
        _mk(repo, "runs/fire-01.txt",
            "# ev\nFIRE scripts/fake.py::check_x\nRESULT red=0 yellow=0\n")
        ok, _l, j = run_cover(repo, src)
        chk("FIRE with all-green body => yellow not counted",
            (not ok) and j["yellow"] > 0 and j["red"] > 0)

        # 5 恢复证据 => 通过, L5 成立
        _mk(repo, "runs/fire-01.txt",
            "# ev\nFIRE scripts/fake.py::check_x\nRESULT red=1\n")
        ok, _l, j = run_cover(repo, src)
        chk("valid ledger => pass", ok and j["l5"] is True, "ok=%s l5=%s" % (ok, j["l5"]))

        # 6 text-only 多于 covered => L5 不成立
        _map(repo, [("D1", 4, "C1.1", "C1.2", 2), ("D2", 6, "-", "C1.3", 5)],
             [("C1.1", "scripts/fake.py::check_x", "covered"),
              ("C1.2", "scripts/fake.py::check_x", "text-only"),
              ("C1.3", "doc.md", "text-only")], (10, 2, 1, 2))
        ok, _l, j = run_cover(repo, src)
        chk("text-only > covered => L5 fail", (not ok) and j["l5"] is False)

        # 7 判据指向不存在 => 红
        _map(repo, good_dom,
             [("C1.1", "scripts/nope.py::check_x", "covered"),
              ("C1.2", "scripts/fake.py::check_x", "covered"),
              ("C1.3", "doc.md", "text-only")], (10, 2, 2, 1))
        ok, _l, _j = run_cover(repo, src)
        chk("dangling ref => red", not ok)

        # 8 合计行与实测不符 => 红
        _map(repo, good_dom, good_item, (10, 2, 5, 1))
        ok, _l, _j = run_cover(repo, src)
        chk("total mismatch => red", not ok)

        # 9 分母漂移: 表里写 97, 母版只有 10 => 红
        _map(repo, [("D1", 50, "C1.1,C1.2", "-", 48), ("D2", 47, "-", "C1.3", 46)],
             good_item, (97, 2, 2, 1))
        ok, _l, _j = run_cover(repo, src)
        chk("denominator drift => red", not ok)

        # 10 域表列了条目表里没有的东西 => 红(两边各写一遍必然漂移)
        _map(repo, [("D1", 4, "C1.1,C1.2,C9.9", "-", 1), ("D2", 6, "-", "C1.3", 5)],
             good_item, (10, 2, 3, 1))
        ok, _l, _j = run_cover(repo, src)
        chk("domain lists unknown id => red", not ok)

        # 11 读不到母版 => 分母标未核验, 但仍要算得出账内残差
        _map(repo, good_dom, good_item, (10, 2, 2, 1))
        ok, lines, j = run_cover(repo, None)
        chk("no source => absent as residual, marked unverified",
            ok and j["absent"] == 7 and j["source_verified"] is False,
            "ok=%s absent=%s verified=%s" % (ok, j["absent"], j["source_verified"]))

        # 12/13 参数必须被读进去, 不许静默吞掉后照常 rc=0。
        # 「没传母版」和「母版路径打错」是两件事: 前者是诚实的账内自洽,
        # 后者是用户以为自己算了母版、其实一次没读。
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            rc_nofile = main(["--source", os.path.join(base, "没有这个文件.md"), repo])
        chk("--source 指向不存在的文件 => rc=2(不许退化成'未核验')",
            rc_nofile == 2, "rc=%s" % rc_nofile)

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            rc_noarg = main(["--json"])
        chk("--json 缺路径 => rc=2", rc_noarg == 2, "rc=%s" % rc_noarg)
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
    source = None
    if "--source" in argv:
        i = argv.index("--source")
        if i + 1 >= len(argv) or argv[i + 1].startswith("--"):
            print("--source 需要一个文件路径; 不给就别写这个参数(分母退回账内合计行)")
            return 2
        source = argv[i + 1]
        if not os.path.exists(source):
            # 上一版把"路径打错"与"没传母版"当成同一件事:
            # 都退化成"分母未核验"并 rc=0 —— 于是写了 --source 的人会以为算过母版,
            # 其实一次都没读。这是这一族工具最典型的假绿形状: 参数被吞, 输出照旧。
            print("--source 指向的文件不存在: %s" % source)
            return 2
    if "--json" in argv:
        i = argv.index("--json")
        if i + 1 >= len(argv) or argv[i + 1].startswith("--"):
            print("--json 需要一个输出路径(不给就别写这个参数)")
            return 2
    skip = set()
    for flag in ("--source", "--json"):
        if flag in argv:
            i = argv.index(flag)
            if i + 1 < len(argv):
                skip.add(argv[i + 1])
    args = [a for a in argv[1:] if not a.startswith("--") and a not in skip]
    root = args[0] if args else "."
    if not os.path.isdir(root):
        print("not a dir: %s" % root)
        return 2
    ok, lines, j = run_cover(root, source)
    print("\n".join(lines))
    if "--json" in argv:
        i = argv.index("--json")
        if i + 1 < len(argv):
            # 只存文件名: 绝对路径会带出本机用户名与目录结构, 而它对复核没有用。
            j["source"] = os.path.basename(source) if source else None
            with open(argv[i + 1], "w", encoding="utf-8", newline="\n") as f:
                json.dump(j, f, ensure_ascii=False, indent=1, sort_keys=True)
                f.write("\n")
            print("WROTE %s" % argv[i + 1])
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
