#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""falsify.py - 检查器的检查器。验证闸门真的会否决。

用法:
    python falsify.py --checker "python scripts/gate.py {root}" \
                      --good <干净样本目录> --bad <故意做坏的目录>
    python falsify.py --selftest

它在测什么:
    在 bad 上, checker 必须非零退出  -> 否则闸门是装饰 (从不否决)
    在 good 上, checker 必须零退出    -> 否则闸门误伤 (见谁都红)

两个都要过。只测一边的闸门, 只证明了一半。
{root} 会被替换成对应目录路径。

为什么这件仪器最该先有:
    一个从不否决的闸门, 在报告里和"没有闸门"长得完全一样。
    只看它输出"全绿", 分不清是"没问题"还是"根本没在看"。
"""

import os
import sys
import shutil
import tempfile
import subprocess


def run_checker(cmd_tpl, root, timeout=120):
    cmd = cmd_tpl.replace("{root}", root)
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout)
        return p.returncode, (p.stdout or b"") + (p.stderr or b"")
    except subprocess.TimeoutExpired:
        return -9, b"TIMEOUT"


def falsify(cmd_tpl, good, bad):
    """返回 (ok, rows)。ok=False 表示判据失效。"""
    rows = []
    ok = True

    rc_bad, out_bad = run_checker(cmd_tpl, bad)
    passed_on_bad = (rc_bad == 0)
    rows.append(("bad sample must be rejected", not passed_on_bad,
                 "rc=%d" % rc_bad))
    if passed_on_bad:
        ok = False

    rc_good, out_good = run_checker(cmd_tpl, good)
    failed_on_good = (rc_good != 0)
    rows.append(("good sample must pass", not failed_on_good,
                 "rc=%d" % rc_good))
    if failed_on_good:
        ok = False

    if passed_on_bad:
        rows.append(("diagnosis", False, "闸门在坏样本上放行 = 装饰"))
    if failed_on_good:
        rows.append(("diagnosis", False, "闸门在好样本上报错 = 误伤"))

    return ok, rows, out_bad, out_good


# ---------------- selftest ----------------

def _mk(root, rel, text):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p) or root, exist_ok=True)
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def selftest():
    """造两种闸门: 真的和假的。断言 falsify 能区分它们。"""
    base = tempfile.mkdtemp(prefix="fal_st_")
    results = []

    def chk(name, cond, detail=""):
        results.append((name, bool(cond), detail))

    try:
        good = os.path.join(base, "good")
        bad = os.path.join(base, "bad")
        _mk(good, "ok.txt", "fine\n")
        _mk(bad, "ok.txt", "fine\n")
        _mk(bad, "leak.txt", "sk" + "-abcdefghijklmnopqrstuvwxyz01\n")

        real = os.path.join(base, "real_check.py")
        _mk(base, "real_check.py",
            "import os,sys\n"
            "root=sys.argv[1]\n"
            "hit=False\n"
            "for dp,_,fs in os.walk(root):\n"
            "    for f in fs:\n"
            "        t=open(os.path.join(dp,f),encoding='utf-8',errors='replace').read()\n"
            "        if 'sk'+'-' in t: hit=True\n"
            "sys.exit(1 if hit else 0)\n")

        fake = os.path.join(base, "fake_check.py")
        _mk(base, "fake_check.py", "import sys\nsys.exit(0)\n")

        py = sys.executable

        ok_real, rows_real, _, _ = falsify('"%s" "%s" {root}' % (py, real), good, bad)
        chk("real gate => criterion holds", ok_real,
            "; ".join("%s:%s" % (n, "ok" if c else "FAIL") for n, c, _ in rows_real))

        ok_fake, rows_fake, _, _ = falsify('"%s" "%s" {root}' % (py, fake), good, bad)
        chk("fake gate => caught", not ok_fake, "ok=%s (期望 False)" % ok_fake)

        # 反向闸门: 见谁都红
        always = os.path.join(base, "always_red.py")
        _mk(base, "always_red.py", "import sys\nsys.exit(1)\n")
        ok_over, _, _, _ = falsify('"%s" "%s" {root}' % (py, always), good, bad)
        chk("over-rejecting gate => caught", not ok_over, "ok=%s (期望 False)" % ok_over)

        # 超时视为未通过, 不得静默当作成功
        ok_to, _, _, _ = falsify('"%s" -c "import time;time.sleep(30)"' % py, good, bad)
        chk("timeout not treated as pass", not ok_to, "ok=%s (期望 False)" % ok_to)
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
    if "--checker" not in argv or "--good" not in argv or "--bad" not in argv:
        print("usage: falsify.py --checker \"cmd {root}\" --good <dir> --bad <dir>")
        return 2
    cmd = argv[argv.index("--checker") + 1]
    good = argv[argv.index("--good") + 1]
    bad = argv[argv.index("--bad") + 1]
    for d in (good, bad):
        if not os.path.isdir(d):
            print("not a dir: %s" % d)
            return 2
    ok, rows, out_bad, out_good = falsify(cmd, good, bad)
    for name, cond, detail in rows:
        print("%s %s  %s" % ("PASS" if cond else "FAIL", name, detail))
    print("")
    print("RESULT %s" % ("criterion holds" if ok else "criterion FAILS"))
    if not ok:
        print("--- output on bad sample ---")
        print(out_bad.decode("utf-8", "replace")[:800])
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
