#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""probe.py - 四件通用探针。每条都必须能在一个真实目录上变红。

  SWALLOW  静默吞异常: except 之后只有 pass/continue/return/... , 没有任何处置
  DUP      同一段话同时存在于多份文档(>=80 字符, Jaccard>=0.75): 3 份红 / 2 份黄
           (只管文档。代码里的同段重复是「单文件零依赖」这一取舍的代价,
            归 C1.2 管, 不归这条——一条判据只答一个问题)
  ORPHAN   文档不可达: 根级 *.md 与 cases/*/case.md 从 README.md 走不到
  DEPS     第三方 import 未声明: 有 import 而仓库里没有 RUNTIME.md

用法:
    python probe.py <root>
    python probe.py --selftest

四条共同纪律(与 gate/shape/cover 一致):
  1. 扫描面为 0 => N/A 并单独打出 SCAN 行, 绝不报 PASS。扫 0 个文件仍报绿,
     与「从不否决的闸门」是同一种东西。
  2. 每个红/黄都要带 文件:行 或 具体条目。没有出处的红不算红, 算噪声。
  3. 允许就地豁免, 但理由必须写在案发现场: `# noqa: swallow <理由>`(>=4 字)。
     豁免计入 YELLOW, 不装成 PASS —— 有理由的静默跳过仍然是静默跳过。
  4. 自测必须同时验「该红会红」与「不该红不红」。只验后者等于没测这条判据。
"""

import ast
import json
import os
import re
import shutil
import sys
import tempfile

SKIP_DIR = {".git", "__pycache__", "node_modules", ".venv", "venv",
            "dist", "build", ".idea", ".vscode", ".mypy_cache", ".pytest_cache"}

CODE_EXT = (".py",)
DOC_EXT = (".md",)

DUP_MIN_CHARS = 80
DUP_JACCARD = 0.75
DUP_RED_FILES = 3
DUP_YELLOW_FILES = 2
COMMON_SHINGLE = 50   # 出现在 >50 段的 shingle 视为公共短语, 不参与相似度

NOQA_RE = re.compile(r"#\s*noqa:\s*swallow\s+(\S.{3,})")

# 只收顶层模块名就够: 判的是「有没有装这个包」, 不是「从哪个子模块来」。
STDLIB = set("""
abc argparse array ast asyncio base64 binascii bisect builtins bz2 calendar cmath
cmd codecs collections colorsys configparser contextlib copy csv ctypes datetime
decimal difflib dis doctest email enum errno faulthandler filecmp fileinput fnmatch
fractions ftplib functools gc getopt getpass gettext glob gzip hashlib heapq hmac
html http imaplib importlib inspect io ipaddress itertools json keyword linecache
locale logging lzma mailbox math mimetypes mmap multiprocessing netrc numbers
operator optparse os pathlib pickle pipes pkgutil platform plistlib poplib pprint
profile pstats queue quopri random re readline reprlib runpy sched secrets select
selectors shelve shlex shutil signal site smtplib socket socketserver sqlite3 ssl
stat statistics string struct subprocess sys sysconfig tarfile tempfile textwrap
threading time timeit token tokenize traceback tracemalloc types typing unicodedata
unittest urllib uu uuid venv warnings wave weakref webbrowser xml zipfile zlib
""".split())


# ---------------- 采集 ----------------

def read_text(path):
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError:
        return None
    if b"\x00" in raw[:4096]:
        return None
    return raw.decode("utf-8", "replace")


def collect(root, exts):
    out = []
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in SKIP_DIR]
        for f in sorted(fn):
            if f.endswith(exts):
                out.append(os.path.join(dp, f))
    out.sort()
    return out


def rel(root, p):
    return os.path.relpath(p, root).replace("\\", "/")


# ---------------- 1 SWALLOW ----------------

def check_swallow(root, files):
    """except 之后没有任何处置 => 命中。返回 (state, detail, hits, scan)。"""
    hits, exempt, excepts = [], [], 0
    for p in files:
        txt = read_text(p)
        if txt is None:
            continue
        lines = txt.splitlines()
        for i, line in enumerate(lines):
            m = re.match(r"^(\s*)except\b[^:]*:\s*(#.*)?$", line)
            if not m:
                continue
            excepts += 1
            ind = len(m.group(1))
            j = i + 1
            while j < len(lines) and not lines[j].strip():
                j += 1
            if j >= len(lines):
                continue
            body = lines[j]
            bind = len(body) - len(body.lstrip())
            if bind <= ind:
                continue
            if not re.match(r"^\s*(pass|continue|return|\.\.\.)\s*(#.*)?$", body):
                continue
            loc = "%s:%d" % (rel(root, p), i + 1)
            if NOQA_RE.search(line):
                exempt.append(loc)
            elif NOQA_RE.search(body):
                exempt.append(loc)
            else:
                hits.append(loc)
    scan = len(files)
    if scan == 0:
        return "N/A", "no .py files", [], 0
    if hits:
        det = "excepts=%d bare=%d %s" % (excepts, len(hits), ",".join(hits[:4]))
        return "RED", det, hits, scan
    if exempt:
        return "YELLOW", "bare=%d all exempted (%s)" % (len(exempt), ",".join(exempt[:3])), [], scan
    return "PASS", "excepts=%d all handled" % excepts, [], scan


# ---------------- 2 DUP ----------------

def _paragraphs(txt):
    out, buf = [], []
    for line in txt.splitlines():
        if line.strip():
            buf.append(line.strip())
        else:
            if buf:
                out.append("".join(buf))
                buf = []
    if buf:
        out.append("".join(buf))
    return out


def _norm(s):
    return re.sub(r"\s+", "", s)


def _shingles(s, k=4):
    return set(s[i:i + k] for i in range(len(s) - k + 1))


def check_dup(root, files):
    """跨文件重复段落。返回 (state, detail, groups, scan)。"""
    paras = []          # [(file, idx, norm_text, shingles)]
    for p in files:
        txt = read_text(p)
        if txt is None:
            continue
        for idx, para in enumerate(_paragraphs(txt)):
            if "dup: ignore" in para:
                continue
            n = _norm(para)
            if len(n) < DUP_MIN_CHARS:
                continue
            paras.append((rel(root, p), idx, n, _shingles(n)))
    scan = len(files)
    if scan == 0:
        return "N/A", "no .md/.py files", [], 0
    pairs = []
    # 高频 shingle(如"的"、"判据")对判别力为零, 计进去只会造出假重复。
    # 用倒排索引 + 频率上限: 既是提速, 也是精度——这条判据以前在中文短段上误报过。
    seen = {}
    for i, p in enumerate(paras):
        for s in p[3]:
            seen.setdefault(s, []).append(i)
    shared = {}
    for _s, ids in seen.items():
        if len(ids) > COMMON_SHINGLE:
            continue
        for x in range(len(ids)):
            for y in range(x + 1, len(ids)):
                k = (ids[x], ids[y])
                shared[k] = shared.get(k, 0) + 1
    for (a, b), _n in shared.items():
        sa, sb = paras[a][3], paras[b][3]
        j = len(sa & sb) / float(len(sa | sb))
        if j >= DUP_JACCARD and paras[a][0] != paras[b][0]:
            pairs.append((a, b, j))
    if not pairs:
        return "PASS", "paras=%d no cross-file pair >=%.2f" % (len(paras), DUP_JACCARD), [], scan
    # 并查集聚簇
    parent = list(range(len(paras)))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for a, b, _j in pairs:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb
    clusters = {}
    for a, b, _j in pairs:
        # 两个端点都要进簇。只收 a 会把 a-b-c 判成 2 份文件, 于是 3 份永远不红。
        for m in (a, b):
            clusters.setdefault(find(a), set()).add(m)
    groups = []
    for _root, members in clusters.items():
        fs = sorted(set(paras[m][0] for m in members))
        where = sorted("%s:p%d" % (paras[m][0], paras[m][1]) for m in members)
        groups.append((fs, where))
    red = [g for g in groups if len(g[0]) >= DUP_RED_FILES]
    yellow = [g for g in groups if len(g[0]) == DUP_YELLOW_FILES]
    if red:
        det = "%d clusters in >=%d files e.g. %s" % (len(red), DUP_RED_FILES, ",".join(red[0][1][:3]))
        return "RED", det, red, scan
    if yellow:
        det = "%d clusters in 2 files e.g. %s" % (len(yellow), ",".join(yellow[0][1][:2]))
        return "YELLOW", det, [], scan
    return "PASS", "paras=%d clusters=%d" % (len(paras), len(groups)), [], scan


# ---------------- 3 ORPHAN ----------------

def check_orphan(root, docs):
    """根级 *.md 与 cases/*/case.md 必须从 README.md 可达(按文件名提及建边)。"""
    if not docs:
        return "N/A", "no .md files", [], 0
    base = {}
    for p in docs:
        base[rel(root, p)] = read_text(p) or ""
    if "README.md" not in base:
        return "RED", "README.md missing: no entry, every doc is orphan", [], len(docs)
    graph = {}
    for r, txt in base.items():
        outs = set()
        for other in base:
            if other == r:
                continue
            if os.path.basename(other) in txt:
                outs.add(other)
        graph[r] = outs
    seen, stack = {"README.md"}, ["README.md"]
    while stack:
        cur = stack.pop()
        for nxt in graph.get(cur, ()):
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    orphan = sorted(set(base) - seen)
    if orphan:
        return ("RED", "%d/%d unreachable from README.md: %s"
                % (len(orphan), len(base), ",".join(orphan[:4])), orphan, len(docs))
    return "PASS", "reachable=%d/%d" % (len(seen), len(base)), [], len(docs)


# ---------------- 4 DEPS ----------------

def _imports(path):
    """返回 (顶层模块集合, 延迟导入集合)。延迟导入单列: 缺包时 --help 还起得来。"""
    txt = read_text(path)
    if txt is None:
        return set(), set()
    try:
        tree = ast.parse(txt)
    except SyntaxError:
        return set(), set()
    top, late = set(), set()

    def add(node, bag):
        if isinstance(node, ast.Import):
            for a in node.names:
                bag.add(a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                return
            if node.module:
                bag.add(node.module.split(".")[0])

    for node in tree.body:
        add(node, top)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            for sub in ast.walk(node):
                add(sub, late)
    return top, late - top


def check_deps(root, files):
    """非标准库、非本仓模块的 import 必须登记在 RUNTIME.md。"""
    if not files:
        return "N/A", "no .py files", [], 0
    local = set()
    for p in files:
        local.add(os.path.splitext(os.path.basename(p))[0])
    runtime = os.path.join(root, "RUNTIME.md")
    declared = read_text(runtime) if os.path.exists(runtime) else None
    third, top_bad = {}, []
    for p in files:
        top, late = _imports(p)
        for name in sorted(top | late):
            if name in STDLIB or name in local or name.startswith("_"):
                continue
            third.setdefault(name, []).append(rel(root, p))
            if name in top:
                top_bad.append(name)
    if not third:
        return "PASS", "files=%d no third-party import" % len(files), [], len(files)
    if declared is None:
        return ("RED", "third-party %s but no RUNTIME.md (undeclared)"
                % ",".join(sorted(third)[:4]), sorted(third), len(files))
    miss = [n for n in sorted(third) if n not in declared]
    if miss:
        return ("RED", "not in RUNTIME.md: %s" % ",".join(miss[:4]), miss, len(files))
    return "PASS", "third-party %s declared (module-level: %s)" % (
        ",".join(sorted(third)), ",".join(sorted(set(top_bad))) or "-"), [], len(files)


# ---------------- 汇总 ----------------

def run_probe(root):
    code = collect(root, CODE_EXT)
    docs = collect(root, DOC_EXT)
    rows = []
    rows.append(("SWALLOW",) + check_swallow(root, code)[:2])
    rows.append(("DUP",) + check_dup(root, docs)[:2])
    rows.append(("ORPHAN",) + check_orphan(root, docs)[:2])
    rows.append(("DEPS",) + check_deps(root, code)[:2])
    cnt = {"PASS": 0, "RED": 0, "YELLOW": 0, "N/A": 0}
    lines = ["probe root=%s" % os.path.basename(os.path.abspath(root)),
             "SCAN files=%d docs=%d subjects=%d" % (len(code), len(docs), len(code) + len(docs))]
    for name, st, det in rows:
        cnt[st] = cnt.get(st, 0) + 1
        lines.append("%-8s %-6s %s" % (name, st, det))
    lines.append("ITEMS " + " ".join("%s=%s" % (n, s) for n, s, _d in rows))
    lines.append("RESULT red=%d yellow=%d na=%d" % (cnt["RED"], cnt["YELLOW"], cnt["N/A"]))
    return (cnt["RED"] == 0), lines, cnt


# ---------------- selftest ----------------

def _mk(root, relp, text):
    p = os.path.join(root, relp)
    d = os.path.dirname(p)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def selftest():
    base = tempfile.mkdtemp(prefix="probe_st_")
    res = []

    def chk(name, cond, detail=""):
        res.append((name, bool(cond), detail))

    try:
        # 1 SWALLOW: 必须真红, 且豁免后必须转黄(豁免不是消失)
        a = os.path.join(base, "sw")
        _mk(a, "bad.py", "def f(p):\n    try:\n        open(p)\n    except OSError:\n        pass\n")
        st, det, _h, _s = check_swallow(a, collect(a, CODE_EXT))
        chk("swallow: bare except => RED", st == "RED", "%s %s" % (st, det))
        _mk(a, "bad.py",
            "def f(p):\n    try:\n        open(p)\n    except OSError:  # noqa: swallow 文件可能不存在, 跳过是语义\n        pass\n")
        st, det, _h, _s = check_swallow(a, collect(a, CODE_EXT))
        chk("swallow: exempted => YELLOW not PASS", st == "YELLOW", "%s %s" % (st, det))
        _mk(a, "bad.py", "def f(p):\n    try:\n        open(p)\n    except OSError as e:\n        raise\n")
        st, _d, _h, _s = check_swallow(a, collect(a, CODE_EXT))
        chk("swallow: handled => PASS", st == "PASS", st)

        # 2 DUP: 3 份 => 红; 2 份 => 黄; 1 份 => PASS
        d = os.path.join(base, "dup")
        para = ("\u8fd9\u4e00\u6bb5\u662f\u4e00\u6a21\u4e00\u6837\u7684\u8bdd, "
                "\u5199\u5728\u591a\u4efd\u6587\u4ef6\u91cc\u9760\u4eba\u8bb0, "
                "\u4e00\u65e6\u6f02\u79fb\u5c31\u6ca1\u4eba\u77e5\u9053\u54ea\u4efd\u662f\u6d3b\u7684\u3002"
                "\u5224\u636e\u53ea\u80fd\u843d\u5728\u91cd\u590d\u672c\u8eab\u4e0a\u3002") * 2
        for n in ("a", "b", "c"):
            _mk(d, "%s.md" % n, "# %s\n\n%s\n" % (n, para))
        st, det, _g, _s = check_dup(d, collect(d, DOC_EXT))
        chk("dup: same para in 3 files => RED", st == "RED", "%s %s" % (st, det))
        os.remove(os.path.join(d, "c.md"))
        st, det, _g, _s = check_dup(d, collect(d, DOC_EXT))
        chk("dup: 2 files => YELLOW", st == "YELLOW", "%s %s" % (st, det))
        os.remove(os.path.join(d, "b.md"))
        st, _d, _g, _s = check_dup(d, collect(d, DOC_EXT))
        chk("dup: 1 file => PASS", st == "PASS", st)

        # 3 ORPHAN: 不可达必须红, 补一条引用必须转绿
        o = os.path.join(base, "orph")
        _mk(o, "README.md", "# r\n\nsee also A.md\n")
        _mk(o, "A.md", "a\n")
        _mk(o, "B.md", "b\n")
        st, det, _x, _s = check_orphan(o, collect(o, DOC_EXT))
        chk("orphan: unreachable => RED", st == "RED", "%s %s" % (st, det))
        _mk(o, "A.md", "a, back to README.md, and B.md\n")
        st, det, _x, _s = check_orphan(o, collect(o, DOC_EXT))
        chk("orphan: linked => PASS", st == "PASS", "%s %s" % (st, det))

        # 4 DEPS: 第三方未声明必须红, 声明后转绿
        p = os.path.join(base, "dep")
        _mk(p, "use.py", "import requests\nimport json\n")
        st, det, _x, _s = check_deps(p, collect(p, CODE_EXT))
        chk("deps: undeclared third-party => RED", st == "RED", "%s %s" % (st, det))
        _mk(p, "RUNTIME.md", "| package | why |\n|---|---|\n| requests | http |\n")
        st, det, _x, _s = check_deps(p, collect(p, CODE_EXT))
        chk("deps: declared => PASS", st == "PASS", "%s %s" % (st, det))

        # 5 扫描面为 0 => N/A, 不许 PASS(假绿就是这里生出来的)
        e = os.path.join(base, "empty")
        os.makedirs(e, exist_ok=True)
        st, _d, _x, sc = check_swallow(e, collect(e, CODE_EXT))
        chk("empty dir => N/A not PASS", st == "N/A" and sc == 0, st)
    finally:
        shutil.rmtree(base, ignore_errors=True)

    ok = sum(1 for _, c, _ in res if c)
    for name, cond, detail in res:
        print("%s %s  %s" % ("PASS" if cond else "FAIL", name, detail))
    print("\nselftest %d/%d" % (ok, len(res)))
    return 0 if ok == len(res) else 1


def main(argv):
    if "--selftest" in argv:
        return selftest()
    args = [a for a in argv[1:] if not a.startswith("--")]
    root = args[0] if args else "."
    if not os.path.isdir(root):
        print("not a dir: %s" % root)
        return 2
    ok, lines, _c = run_probe(root)
    print("\n".join(lines))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
