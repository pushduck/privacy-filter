# TODO

## 网关：可选的输入翻译（未开始）

运行时可选开启，将请求中的用户输入翻译为目标语言（默认英语）后再转发上游；响应原样透传，不修改回复、不注入"用中文回复"等指令。

**已定**

- 翻译后端：外部翻译服务，Google / 微软（Azure Translator）/ DeepL，做成可选实现（接口 + 多后端）。
- 仅 `pf-gateway` 提供，`internal/translate` 新包，`filter` 包不动。

**设计要点**

- 顺序：先脱敏、后翻译，翻译服务只能收到脱敏后的文本。
- 范围白名单比 `contentKeys` 窄：只翻 `role=user` 的纯文本；不翻 `arguments`、tool_result / `output`、`system` / `instructions`、assistant 历史、thinking。
- 占位符保护：脱敏占位符（如 `[电话]`、`[密钥]`）、代码块、URL、路径翻译前换成不可译标记（DeepL 可用 `tag_handling=xml` + ignore_tags，Google/微软用 `notranslate` 标签），翻译后逐个核对，缺失则回退为未翻译的脱敏文本。
- 缓存：按原文哈希缓存译文（LRU），历史消息不重复翻译，也保证结果稳定、不破坏上游 prompt cache。
- 已是目标语言的文本跳过（按字符比例粗判）；一次请求内批量调用。
- 失败处理：默认回退为转发脱敏文本（已脱敏，不泄露原文）；`-translate-strict` 时返回 502。原有 fail-closed 不变。
- 无命中且无翻译时仍逐字节转发原始请求体。

**参数草案**

`-translate`（默认关）、`-translate-to`（默认 `en`）、`-translate-provider`（google|microsoft|deepl）、`-translate-strict`；API Key 仅从环境变量读取（如 `PF_TRANSLATE_API_KEY`），微软另需 region。均支持 `PF_*` 环境变量。

**风险 / 注意**

- 新增数据出口：脱敏后的内容会发给第三方翻译服务，启动时打印 ⚠ 提示，文档写明。
- 延迟：首 token 前多一次翻译往返；费用按字符计。
- 日志：`basic` / `request` 级别不得打印译文；任何级别不得记录翻译 API Key。
- 输入变英文后模型大概率用英文回复（按需求不处理）。

**测试**

`gateway_test.go` 中用假翻译器覆盖：占位符被破坏时回退、`arguments` / tool_result 不翻、缓存命中、失败回退与 strict 模式。
