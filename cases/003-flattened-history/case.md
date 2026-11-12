# 003 · 上传「成功」、文件齐全、CI 全绿，但提交历史被压平

## 现场

2026-11-12，用 Git Data API 把本地两个提交推到空仓库（`github.com` 的 443 不可达，
只能用 `api.github.com`）。脚本 `do_push.ps1` 每次跑完都打印：

```
[5/6] commit: <sha>
[6/6] ref updated: refs/heads/main
files  : 9 on main
```

回读方式：

```
GET /repos/<owner>/<repo>/git/ref/heads/main
GET /repos/<owner>/<repo>/git/commits/<sha>
GET /repos/<owner>/<repo>/git/trees/<tree>?recursive=1
GET /repos/<owner>/<repo>/commits?per_page=10
```

原始输出见 `evidence/commits-before-after.txt`。

## 红

文件层面全部正常：**9 个文件都在，字节数与本地逐一相等，CI 三轮全绿**。

但回读提交数量：

```
commits = 1
  f342405  ci: 修 3.8 测试通道（换成能跑的机器，而不是改高版本号）
```

本地有 2 个提交，远端只剩 1 个。`init` 那条不见了。

根因在脚本第 149 行：

```powershell
try { Api 'GET' "/repos/$owner/$RepoName/git/ref/heads/main" $null | Out-Null }
catch { ... }
```

它**只探测 GET 成功还是失败，却从不把返回的 ref.sha 赋给 `$parentSha`**。
于是非空仓库时 `$parentSha` 恒为 `$null`，每次生成的都是孤儿提交，
再 force 更新 ref —— 每推一次，历史就被压平一次。

这个缺陷完全躲过了此前所有检查：文件数对、字节对、CI 绿。
因为那些断言都在看**内容**，没人看**结构**。

## 判据

对应 METHOD「六 · 判据必须能当场变红」。

「文件在不在」这条断言，从上线到现在从未红过 —— 它在这件事上必然永远是绿的，
因为文件确实都在。一条永不否决的断言，对这类故障等于不存在。

换句话说：这条案例证明的不是「有个 bug」，而是「我有一批断言，它们看不见结构性丢失」。

## 修法

两件事：

1. **修脚本**：取回 `ref.object.sha` 并作为 `parent`，修完后每次上传都在前一个提交之上
2. **加一条会红的断言**：`verify_remote.py` 逐文件比对本地与远端的 **blob sha**，
   不等即输出 REJECT；同时核对提交链的 `parents` 字段是否为空

修完回读：

```
commits = 2
  9041e8d  ci: 修 3.8 测试通道（换成能跑的机器，而不是改高版本号）
  ab449a7  init: 七条判据 + 三件仪器 (junyi-lite v0.1)

parents = ['ab449a7']
```

验证方式：任何一次上传后，必须同时满足「文件数正确」**与**「提交数增加 1」。
只满足前者，就是这次的事故。
