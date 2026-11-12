# 001 · 状态码 200 不等于成功

## 现场

2026-11-12，本机 Windows，PowerShell 5.1，用 curl 探测 `github.com` 网页是否可达。
系统 DNS 只返回一个 IP，且该 IP 的 443 不通，于是逐个试其它已知 IP。

命令（对三个 IP 各跑一次，`-o NUL` 丢弃正文，只取指标）：

```
curl --noproxy "*" --resolve "github.com:443:<IP>" -sSL --max-time 40 -o NUL \
  -w "code=%{http_code} size=%{size_download} t=%{time_total}s" https://github.com
```

原始输出见 `evidence/curl-200-zero-bytes.txt`。

## 红

三行结果长这样：

```
code=200 size=0 t=40.002363s
code=000 size=0 t=26.721139s
code=000 size=0 t=40.009689s
```

第一行我当时的结论是「通了」，还据此对用户承诺「我起个代理帮你打开」。

这是错的。`code=200` 只说明拿到了状态行；`size=0` 说明正文一个字都没到。
真正的信号是**两个数一起看**：200 + 0 字节 = 被截断，不是成功。

后果不是纸面错误：基于这个假成功，我给出的方案（起本地代理打开网页）根本不可能成立，
因为代理只是换一种方式连同一批 IP。用户会照着做，然后第二次失败。

## 判据

对应 METHOD「二 · 任何数字要有两个独立口径」。

`code` 与 `size_download` 是同一次请求的两个独立读数。
只看 `code`，链路被截断时读出「成功」；只看 `size`，
分不清「服务端本来就没内容」和「内容在半路被丢掉」。

## 修法

把「可达」的定义从 `code==200` 收紧为 `code==200 且 size>0`，然后重建阳性对照：

- `raw.githubusercontent.com` 取回 README：**5534 字节**，sha256 与本地相同
- `codeload.github.com` 取回整包：**13985 字节**，解压 9 文件可运行

有了这两个阳性样本，才能判定 `github.com` 主站是「真切不通」，
而不是「我的判据坏了」——这正是 METHOD 第三条「报零要先排三件事」的同一条要求。

验证方式：重跑上面的命令，任何被判为「可达」的请求必须同时满足 size>0。
