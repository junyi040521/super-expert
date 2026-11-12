#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pack_det.py - 确定性打包。同样的树, 必须打出同样的字节。

用法:
    python pack_det.py <src_dir> <out_dir> [--name NAME]
    python pack_det.py <zip> --verify <src_dir>
    python pack_det.py --selftest

为什么需要它:
    普通 zip 会把 mtime、创建系统、权限位、文件顺序一起写进去。
    内容没变, 字节变了 => "下载包与源不一致" 永远查不清。
    固定的四项: 时间戳 / create_system / external_attr / 路径字典序。
"""

import os
import sys
import json
import shutil
import zipfile
import tempfile
import hashlib

FIXED_DT = (1980, 1, 1, 0, 0, 0)   # zip 的最早合法时间, 不随环境变
CREATE_SYS = 3                      # 3 = unix, 0 = MS-DOS, 不固定就会跨机器漂
EXTERNAL_ATTR = (0o100644 << 16)    # 普通文件 0644
SKIP_DIR = {".git", "__pycache__", "node_modules", ".venv", "venv", "dist", "build"}


def collect(src):
    """返回排序后的相对路径列表。排序是确定性的第一步。"""
    out = []
    for dirpath, dirnames, filenames in os.walk(src):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIR)
        for fn in filenames:
            if fn.endswith((".pyc", ".pyo")):
                continue
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, src).replace("\\", "/")
            out.append(rel)
    return sorted(out)


def build(src, dst_zip):
    files = collect(src)
    # 产物自纳入防护: 输出文件本身不得进包
    out_real = os.path.realpath(dst_zip)
    files = [r for r in files if os.path.realpath(os.path.join(src, r)) != out_real]

    with zipfile.ZipFile(dst_zip, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for rel in files:
            full = os.path.join(src, rel)
            zi = zipfile.ZipInfo(rel, date_time=FIXED_DT)
            zi.create_system = CREATE_SYS
            zi.external_attr = EXTERNAL_ATTR
            zi.compress_type = zipfile.ZIP_DEFLATED
            with open(full, "rb") as f:
                zf.writestr(zi, f.read())
    return files


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def entry_digest(path):
    """条目级指纹: 名字 + 大小 + 内容哈希, 与 zip 容器无关。"""
    with zipfile.ZipFile(path) as zf:
        rows = []
        for info in zf.infolist():
            h = hashlib.sha256(zf.read(info.filename)).hexdigest()[:16]
            rows.append((info.filename, info.file_size, info.date_time, h))
    return rows


def verify(zip_path, src):
    """重打一份到临时位置, 与给定 zip 逐字节比对。"""
    tmp = tempfile.mkdtemp(prefix="packdet_")
    try:
        again = os.path.join(tmp, "re.zip")
        files = build(src, again)
        h1 = sha256(zip_path)
        h2 = sha256(again)
        ok_bytes = h1 == h2
        d1 = entry_digest(zip_path)
        d2 = entry_digest(again)
        ok_entries = d1 == d2
        return ok_bytes, ok_entries, files, h1, h2
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------- selftest ----------------

def _mk(root, rel, text):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p) or root, exist_ok=True)
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def selftest():
    base = tempfile.mkdtemp(prefix="pack_st_")
    results = []

    def chk(name, cond, detail=""):
        results.append((name, bool(cond), detail))

    try:
        src = os.path.join(base, "src")
        out = os.path.join(base, "out")
        os.makedirs(out, exist_ok=True)
        _mk(src, "b.txt", "second\n")
        _mk(src, "a.txt", "first\n")
        _mk(src, "sub/c.txt", "third\n")

        z1 = os.path.join(out, "p1.zip")
        f1 = build(src, z1)
        chk("collect sorted", f1 == ["a.txt", "b.txt", "sub/c.txt"], str(f1))

        z2 = os.path.join(out, "p2.zip")
        build(src, z2)
        chk("two builds identical", sha256(z1) == sha256(z2),
            sha256(z1)[:12] + " vs " + sha256(z2)[:12])

        # 改 mtime 不影响字节
        os.utime(os.path.join(src, "a.txt"), (1_700_000_000, 1_700_000_000))
        z3 = os.path.join(out, "p3.zip")
        build(src, z3)
        chk("mtime change does not alter bytes", sha256(z1) == sha256(z3),
            "mtime-independent")

        # 改内容必须变字节
        _mk(src, "a.txt", "first-changed\n")
        z4 = os.path.join(out, "p4.zip")
        build(src, z4)
        chk("content change alters bytes", sha256(z1) != sha256(z4), "differs")

        # verify 对未改的树返回 True
        _mk(src, "a.txt", "first\n")
        ok_bytes, ok_entries, _, h1, h2 = verify(z1, src)
        chk("verify true on rebuild", ok_bytes and ok_entries,
            h1[:12] + " == " + h2[:12])

        # 产物自纳入: 把输出目录放进源目录也不能把自己打进去
        src2 = os.path.join(base, "src2")
        _mk(src2, "x.txt", "x\n")
        inside = os.path.join(src2, "self.zip")
        build(src2, inside)
        with zipfile.ZipFile(inside) as zf:
            names = zf.namelist()
        chk("no self-inclusion", "self.zip" not in names, str(names))

        # 固定时间戳检查
        with zipfile.ZipFile(z1) as zf:
            dts = {i.date_time for i in zf.infolist()}
        chk("all timestamps fixed", dts == {FIXED_DT}, str(dts))
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
    if "--verify" in argv:
        i = argv.index("--verify")
        if i + 1 >= len(argv):
            print("usage: pack_det.py <zip> --verify <src>")
            return 2
        zip_path, src = argv[1], argv[i + 1]
        ok_bytes, ok_entries, files, h1, h2 = verify(zip_path, src)
        print("files=%d" % len(files))
        print("zip   sha256=%s" % h1)
        print("rebuild sha256=%s" % h2)
        print("bytes_match=%s entries_match=%s" % (ok_bytes, ok_entries))
        return 0 if (ok_bytes and ok_entries) else 1

    if len(argv) < 3:
        print("usage: pack_det.py <src> <out_dir> [--name NAME]")
        return 2
    src, out_dir = argv[1], argv[2]
    name = "package"
    if "--name" in argv:
        name = argv[argv.index("--name") + 1]
    os.makedirs(out_dir, exist_ok=True)
    zpath = os.path.join(out_dir, name + ".zip")
    files = build(src, zpath)
    h = sha256(zpath)
    with open(zpath + ".sha256", "w", encoding="utf-8", newline="\n") as f:
        f.write("%s  %s.zip\n" % (h, name))
    print("files=%d" % len(files))
    print("zip=%s" % zpath)
    print("sha256=%s" % h)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
