# 覆盖声明

这个仓库只有 17 个文件。任何「我们实现了某个大体系」的说法，都得先过这张表。

格式：`| 编号 | 名称 | 判据指向 | 类型 |`

- `covered` —— 声明有，且指向的代码**真实存在**（`cover.py` 会去打开文件核对，不是看这句话）
- `text-only` —— 只在文档里被主张，没有可执行判据
- 未列出的 —— 一律算 `absent`

| 编号 | 名称 | 判据指向 | 类型 |
|---|---|---|---|
| C1.2 | 零依赖原语 | scripts/gate.py,scripts/falsify.py,scripts/pack_det.py,scripts/shape.py,scripts/cover.py | covered |
| C2.6 | 资格线与闸门 | scripts/gate.py::CHECKS | covered |
| C3.3 | 口径纪律 | METHOD.md::两个独立口径 | text-only |
| C3.5 | 形态判定 | scripts/shape.py::check_a5 | covered |
| C7.2 | 教训变永久闸门 | cases/001-status-code-not-success/case.md,cases/002-ci-red-is-not-code/case.md,cases/003-flattened-history/case.md | covered |
| C16.1 | 断言强度与变形判定 | scripts/falsify.py::criterion | covered |
| C25.2 | 可重现档位与缓存键契约 | scripts/pack_det.py::sha256 | covered |

<!-- cover-total covered=6 text-only=1 -->

## 只有 7 项，不是 97 项

母版的能力清单是 **97 项 / 31 域**。这个仓库 17 个文件，实际对得上的只有上面 7 项：

- **6 项 covered**：每一格都指向一个能打开、能跑、能变红的文件。
- **1 项 text-only**：口径纪律写在 `METHOD.md` 里，没有代码能替它判定——因为「两个独立口径」要靠人去找第二个来源。
- **90 项 absent**：不是遗漏，是**没有被测物**。比如「事故处置与指挥」「并发所有权」「检索召回」，在静态工具库里没有对应场景。写成判据它们会永远绿，那比不写更糟。

## 读不到母版时

`cover.py` 需要 `--source` 指向母版的能力清单才能算分母。别人 clone 这个仓库后没有那份文件，此时输出 **`unknown`**，不是 `absent`：

> **读不到 ≠ 未覆盖。**

把读不到判成未覆盖，会让「诚实报告」这件事本身变成惩罚——下一次就没人愿意报告了。

## 判据（这条能变红）

| 条件 | 结果 |
|---|---|
| 声明 `covered`，但判据指向的文件或标记不存在 | 红 |
| 声明 `covered` 的脚本没有 `--selftest` | 黄 |
| 本表合计行与实测条目数不符 | 红 |
| `absent < 3 × covered` | L5 不成立（覆盖数过于乐观） |

最后一条是反向的：**未覆盖项必须远多于覆盖项，才算诚实。**
