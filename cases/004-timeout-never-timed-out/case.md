# 004 · 名为「测试超时」的用例，从未触发过超时

## 现场

2026-11-12，Windows 11 / Python 3.13.14，对一个公开克隆的仓库跑全套自测。

```bash
python scripts/falsify.py --selftest
```

`falsify.py` 是「检查器的检查器」：它在坏样本上跑 checker，必须非零；
在好样本上跑，必须为零。它的第 4 条自测叫
`timeout not treated as pass`，尾部注释写着「超时视为未通过, 不得静默当作成功」。

同时注意到一个不相称的数：六件仪器的自测总共 64 条断言，`falsify` 一件就占了
一次 62.8 秒，其余五件加起来不到 2 秒。

## 红

```
$ time python scripts/falsify.py --selftest
PASS real gate => criterion holds  bad sample must be rejected:ok; good sample must pass:ok
PASS fake gate => caught  ok=False (期望 False)
PASS over-rejecting gate => caught  ok=False (期望 False)
PASS timeout not treated as pass  ok=False (期望 False)

selftest 4/4
rc=0 用时 62875ms
```

四条全绿，中间没有任何 `TIMEOUT` 字样，也没有任何一条说明它撞上过超时。
62.8 秒对不上任何一条断言的耗时，除非有一处正在**等待**。

最小复现（`evidence/timeout-selftest-before-after.txt` 原件）：

```
# 最小复现: 一条会睡 3 秒的 checker, 配默认 timeout=120
  rc=0  用时 3.3s  输出=b''
  -> 它没有超时, 正常返回 0。所以'超时'那条自测走的其实不是超时分支。

# 同一个 checker 配 timeout=1
  rc=-9  用时 1.3s  输出=b'TIMEOUT'
  -> 这才叫撞上超时: rc=-9, 且输出里带 TIMEOUT。
```

原来那条自测用的是 `time.sleep(30)`，而 `run_checker` 的默认 `timeout=120`。
30 < 120，所以它 30 秒后**正常返回 0**，`TimeoutExpired` 分支一次都没进过。
它之所以显示 PASS，靠的是另一条规则：闸门在坏样本上返回 0 = 放行 = 装饰。
两个方向各睡 30 秒，正好 60 秒 —— 那 62.8 秒就是它。

**一条自测的名字说它验超时，代码却走到了别的分支上，而且它通过的原因是另一条判据。**
绿灯是真的，被验的东西是假的。

## 判据

对应 METHOD「六 · 判据必须能当场变红」。

这条判据要求：写下的判据必须有一条**能被当场触发的失败路径**。
`timeout not treated as pass` 的失败路径是 `rc == -9`，而它从未走到过 ——
于是这条判据在仓库里存活了很久，一次都没有真正变红过。
用本项目自己的话说：从未红过的判据不是判据。

顺带触发了第二条：METHOD「二 · 任何数字要有两个独立口径」。
「4/4 PASS」是一个口径，「62.8 秒」是另一个口径。
只看前者，这条用例没问题；只看后者，会怀疑哪里在等。两个一对，问题就出来了。

## 修法

1. `run_checker` 把 `timeout` 暴露出来，`falsify()` 透传，默认仍是 120 秒。
2. 那条自测改成 `time.sleep(20)` 配 `timeout=1`，让它**真的**撞墙；断言从
   「结果不是 pass」升级为「结果不是 pass **且** `rc == -9`」，把路径本身锁住。
3. 超时拆成独立的第三态。原来只比较 `rc != 0`，于是：
   - 坏样本上超时 → `rc=-9 != 0` → 被读成「闸门拒绝了坏样本」，这是**假拒绝**；
   - 好样本上超时 → 被诊断成「闸门在好样本上报错 = 误伤」，把排查引向错误方向。
   现在两个方向超时都判 FAIL 并直说「超时：没测出来」，不再冒充拒绝或误伤。
   自测从 4 条增到 6 条，其中一条专门锁「坏样本上超时不算拒绝」。
4. 顺手修掉一个让超时白等的原因：`shell=True` 时子进程是 cmd/sh，
   只 kill 它，底下的真 checker 还活着并占着 stdout 管道，
   `communicate()` 会一直等到真 checker 自己退出 —— 设了 1 秒超时实际等 20 秒。
   改成杀整棵进程树（Windows `taskkill /T /F`，POSIX `killpg`）。

改完的验证：**同一台机器、同一条命令**。

```
$ time python scripts/falsify.py --selftest
PASS hard timeout => rc=-9 (真的撞上了)  rc=-9
PASS timeout not treated as pass  ok=False (期望 False)
PASS timeout => 两个方向都不算通过(含 bad 侧的假拒绝)  bad sample must be rejected=FAIL; good sample must pass=FAIL

selftest 6/6
rc=0 用时 5984ms
```

62.8 秒 → 5.9 秒，断言 4 → 6，并且 `rc=-9` 这条路径第一次真的被执行到。

修完之后回头看的那个数才是重点：**这个仓库当时已经自称最高等级。**
称号没错，只是它名下有一条判据从未变红过 ——
而「从未变红的判据」正是 L4 要挡的东西，它挡的是别人的仓库，不是自己这一条。
