#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cover.py - 覆盖账。声明 covered 就得指向真实存在的代码。红则非零退出。

用法:
    python cover.py <root>                                  # 无母版, 只能判账本自身
    python cover.py --source <capability-inventory.md> <root>
    python cover.py --selftest

三条判定:
    covered    声明有, 且判据指向的文件/标记真实存在(打开文件核对, 不信声明)
    text-only  只在文档里主张, 没有可执行判据
    absent     未声明

L5 反向判据: absent >= 3 x covered 才算诚实。
    未覆盖项必须远多于覆盖项 —— 一个 17 文件的仓库声称覆盖 97 项里的一半,
    只可能是把「提过」当成「做到」。

两条不可省的约束:
  1. 读不到母版 => unknown, 不是 absent。读不到不等于未覆盖;
     把它判成未覆盖, 会让诚实报告变成惩罚, 下次就没人愿意报告了。
  2. 合计行必须与实测条目数一致。账本自己对不上, 是最容易自欺的一种。
"""

import json
import os
import re
import shutil
import sys
import tempfile

SELF = os.path.basename(__file__)
MAP = "MAP.md"
TOTAL_RE = re.compile(r"cover-total\s+covered=(\d+)\s+text-only=(\d+)")
ID_RE = re.compile(r"^(C\d+\.\d+)$")
ITEM_RE = re.compile(r"(?m)^###\s+(C\d+\.\d+)")
L5_RATIO = 3


def read_text(path):
    try:
        with open(path, "rb") as f:
            raw = f.read()
        if b"\x00" in raw[:4096]:
            return None
        return raw.decode("utf-8", "replace")
    except OSError:
        return None


def parse_map(root):
    """返回 (rows, total, failures)。rows 每项 {id,name,ref,kind}。"""
    path = os.path.join(root, MAP)
    if not os.path.exists(path):
        return [], None, ["%s 缺失: 没有覆盖声明, 覆盖账无从谈起" % MAP]
    txt = read_text(path) or ""
    rows, fails = [], []
    for line in txt.splitlines():
        s = line.strip()
        if not s.startswith("|"):
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        if len(cells) < 4:
            continue
        cid = cells[0].strip("` ").strip()
        if not ID_RE.match(cid):
            continue
        kind = cells[3].strip("` ").strip().lower()
        if kind not in ("covered", "text-only"):
            fails.append("%s: 类型只能是 covered / text-only, 读到 %r" % (cid, kind))
            kind = "covered"
        rows.append({"id": cid, "name": cells[1], "ref": cells[2], "kind": kind})
    if not rows:
        fails.append("%s 里没有任何 C<域>.<项> 条目" % MAP)
    m = TOTAL_RE.search(txt)
    total = (int(m.group(1)), int(m.group(2))) if m else None
    if total is None:
        fails.append("%s 缺合计行 <!-- cover-total covered=N text-only=M -->" % MAP)
    return rows, total, fails


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
    """covered 的脚本必须有 --selftest; 文档/目录不计。返回缺失的脚本名。"""
    miss = []
    for one in [x.strip() for x in ref.split(",") if x.strip()]:
        pth = one.split("::", 1)[0].strip("` ")
        if not pth.endswith(".py"):
            continue
        txt = read_text(os.path.join(root, pth.replace("/", os.sep)))
        if txt and "selftest" not in txt:
            miss.append(pth)
    return miss


def count_source(src):
    """母版条目数。读不到返回 None(=> unknown), 不返回 0。"""
    if not src:
        return None
    if not os.path.exists(src):
        return None
    txt = read_text(src)
    if not txt:
        return None
    ids = ITEM_RE.findall(txt)
    return len(ids) if ids else None


def run_cover(root, source=None):
    rows, total, reds = parse_map(root)
    yellows = []
    covered_ids, textonly_ids, unknown_kind = [], [], []
    for r in rows:
        if r["kind"] == "covered":
            f = check_ref(root, r["ref"])
            if f:
                for x in f:
                    reds.append("%s %s: %s" % (r["id"], r["name"][:12], x))
                unknown_kind.append(r["id"])
                continue
            st = check_selftest(root, r["ref"])
            if st:
                yellows.append("%s %s: 无 selftest (%s)"
                               % (r["id"], r["name"][:12], ",".join(st)))
            covered_ids.append(r["id"])
        else:
            textonly_ids.append(r["id"])

    # 账本自身对不上 => 红。这条最容易自欺, 所以单列。
    if total is not None:
        if total[0] != len(covered_ids) + len(unknown_kind):
            reds.append("合计行 covered=%d 与实测 %d 条 covered 不符"
                        % (total[0], len(covered_ids) + len(unknown_kind)))
        if total[1] != len(textonly_ids):
            reds.append("合计行 text-only=%d 与实测 %d 条不符"
                        % (total[1], len(textonly_ids)))

    n_cov = len(covered_ids)
    n_txt = len(textonly_ids)
    n_src = count_source(source)
    lines = ["覆盖账  root=%s" % root]
    if n_src is None:
        lines.append("  母版条目      UNKNOWN  --source 未提供或读不到")
        absent = None
    else:
        absent = n_src - n_cov - n_txt
        lines.append("  母版条目      %d" % n_src)
    lines.append("  covered       %d  %s" % (n_cov, ",".join(covered_ids) or "-"))
    lines.append("  text-only     %d  %s" % (n_txt, ",".join(textonly_ids) or "-"))
    lines.append("  absent        %s" % ("UNKNOWN" if absent is None else absent))
    for r in reds:
        lines.append("RED    %s" % r)
    for y in yellows:
        lines.append("YELLOW %s" % y)

    l5 = None
    if absent is None:
        lines.append("L5     UNKNOWN  \u8bfb\u4e0d\u5230\u6bcd\u7248\u4e0d\u7b49\u4e8e\u672a\u8986\u76d6")
    elif absent < 0:
        lines.append("L5     FAIL     absent \u4e3a\u8d1f: \u58f0\u660e\u6570\u8d85\u8fc7\u6bcd\u7248\u6761\u76ee\u6570")
        l5 = False
    else:
        need = L5_RATIO * n_cov
        l5 = absent >= need
        lines.append("L5     %s     absent=%d %s %d x covered(%d)=%d"
                     % ("PASS" if l5 else "FAIL", absent,
                        "\u003e=" if l5 else "\u003c", L5_RATIO, n_cov, need))

    ok = (not reds) and (l5 is not False)
    lines.append("")
    lines.append("RESULT red=%d yellow=%d l5=%s"
                 % (len(reds), len(yellows),
                    "unknown" if l5 is None else ("pass" if l5 else "fail")))
    return ok, lines, {"covered": covered_ids, "text_only": textonly_ids,
                       "absent": absent, "l5": l5, "red": len(reds)}


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
        body.append("### C1.%d \u80fd\u529b%d\n\n**\u80fd\u529b**\uff1ax\n"
                    "**\u8c03\u7528\u52a8\u4f5c**\uff1ay\n"
                    "**\u5931\u6548\u8fb9\u754c**\uff1az\n" % (i, i))
    p = os.path.join(tmp, "cap.md")
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write("# cap\n\n" + "\n".join(body))
    return p


def _map(root, rows, cov, txt):
    head = ("# M\n\n| \u7f16\u53f7 | \u540d\u79f0 | \u5224\u636e | \u7c7b\u578b |\n"
            "|---|---|---|---|\n")
    body = "".join("| %s | n%s | %s | %s |\n" % (r[0], r[0], r[1], r[2])
                   for r in rows)
    tail = "\n<!-- cover-total covered=%d text-only=%d -->\n" % (cov, txt)
    _mk(root, MAP, head + body + tail)


def selftest():
    """5 项。必须同时验「该红会红」与「L5 会判不诚实」——
    一个永远 PASS 的覆盖账等于没有账。
    """
    base = tempfile.mkdtemp(prefix="cover_st_")
    results = []

    def chk(name, cond, detail=""):
        results.append((name, bool(cond), detail))

    try:
        src = _src_file(base, 10)
        repo = os.path.join(base, "repo")
        _mk(repo, "scripts/fake.py",
            "TOKA = 1\nTOKB = 2\nTOKC = 3\nTOKD = 4\n\ndef selftest():\n    return 0\n")
        _mk(repo, "doc.md", "note\n")

        # 1 无 MAP.md => 红
        ok, _l, _j = run_cover(repo, src)
        chk("no MAP.md => red", not ok, "ok=%s" % ok)

        # 2 声明 covered 但标记不存在 => 红(这是最容易造假的一条)
        _map(repo, [("C1.1", "scripts/fake.py::TOK_ZZZ", "covered")], 1, 0)
        ok, _l, _j = run_cover(repo, src)
        chk("dangling token => red", not ok, "ok=%s" % ok)

        # 3 合计行与实测不符 => 红(账本自己对不上)
        _map(repo, [("C1.1", "scripts/fake.py::TOKA", "covered")], 5, 0)
        ok, _l, _j = run_cover(repo, src)
        chk("total mismatch => red", not ok, "ok=%s" % ok)

        # 4 2 covered / 10 项 => absent 8 >= 3x2 => L5 PASS
        _map(repo, [("C1.1", "scripts/fake.py::TOKA", "covered"),
                    ("C1.2", "scripts/fake.py::TOKB", "covered")], 2, 0)
        ok, _l, j = run_cover(repo, src)
        chk("2 of 10 => L5 pass", ok and j["l5"] is True,
            "ok=%s absent=%s" % (ok, j["absent"]))

        # 5 4 covered / 10 项 => absent 6 < 12 => L5 必须判不成立
        _map(repo, [("C1.1", "scripts/fake.py::TOKA", "covered"),
                    ("C1.2", "scripts/fake.py::TOKB", "covered"),
                    ("C1.3", "scripts/fake.py::TOKC", "covered"),
                    ("C1.4", "scripts/fake.py::TOKD", "covered")], 4, 0)
        ok, _l, j = run_cover(repo, src)
        chk("4 of 10 => L5 fail (too optimistic)", (not ok) and j["l5"] is False,
            "ok=%s absent=%s" % (ok, j["absent"]))

        # 6 读不到母版 => unknown, 不能判成 absent, 也不能因此判红
        _map(repo, [("C1.1", "scripts/fake.py::TOKA", "covered")], 1, 0)
        ok, lines, j = run_cover(repo, None)
        chk("no source => unknown not absent", ok and j["absent"] is None,
            "ok=%s absent=%s" % (ok, j["absent"]))
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
        if i + 1 < len(argv):
            source = argv[i + 1]
    skip = set()
    # 所有带值的 flag 都要跳过它的值, 否则 --json 的路径会被当成 root。
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
            j["items"] = count_source(source)
            with open(argv[i + 1], "w", encoding="utf-8", newline="\n") as f:
                json.dump(j, f, ensure_ascii=False, indent=1, sort_keys=True)
                f.write("\n")
            print("WROTE %s" % argv[i + 1])
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
