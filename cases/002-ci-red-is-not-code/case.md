# 002 · CI 红了，但红在环境安装，不在被测物

## 现场

2026-11-12，GitHub Actions 第一次运行 `.github/workflows/selftest.yml`。
矩阵只有 `python: ["3.8", "3.12"]` 两档，`runs-on: ubuntu-latest`。
查看方式：Actions API 取 run 的 jobs，再下载失败 job 的日志。

```
GET /repos/<owner>/<repo>/actions/runs/<id>/jobs
GET /repos/<owner>/<repo>/actions/jobs/<job_id>/logs
```

原始日志片段见 `evidence/gh-actions-log-38.txt`。

## 红

`python 3.12` 绿，`python 3.8` 红。但红的**位置**是：

```
Set up job                  success
Run actions/checkout@v4     success
Run actions/setup-python@v5 failure      <-- 红在这里
三件仪器自测                 skipped
```

日志原文：

```
##[error]The version '3.8' with architecture 'x64' was not found for Ubuntu 26.04.
```

被测物（三个脚本）一行都没跑。它们被 skipped，不是 failed。

如果按「CI 红了 ⇒ 代码有问题」去改，会去改根本没被执行过的 Python 代码，
改到天亮也不会变绿。

## 判据

对应 METHOD「五 · 判据要指向被测物，不是指向你想象的位置」。

判据的位置决定了你排查的方向。这条红指向的是 runner 环境，
不是被测物；把它读成「代码错」，就是判据指错了位置。

## 修法

不改被测物，改判据的落点：

1. 矩阵加 `os` 维度：`3.8 → ubuntu-22.04`（那里有 3.8 的预编译包），`3.12 → ubuntu-latest`
2. 另加一个 `py38-syntax-guard` job：用 `ast.parse(feature_version=(3, 8))` 做静态守卫，
   即使哪天 3.8 的 runner 彻底下架，声明也不会悄悄失效

改完 `python 3.8 @ ubuntu-22.04` 与 `python 3.12 @ ubuntu-latest` 同时绿，
且两个 job 的「三件仪器自测」步骤是 `success` 而不是 `skipped`——
**看 skipped 还是 success，是这条判据的验证方式**。

顺带记一个不用改的结论：3.8 的语法兼容性静态检查结果是 0 处不兼容，
所以「代码本来就能在 3.8 跑」是真的，缺的只是测试通道。
