# cn-direct-rules

中国大陆公网直连规则。人工规则与 V2Fly 中国域名数据合并，IPv4/IPv6 公网快照和域名快照每天自动更新、校验、生成并发布。

## Shadowrocket 一键安装

[![一键安装 Shadowrocket](https://img.shields.io/static/v1?label=一键安装&message=CN%20Direct%20完整模块&color=grey&logo=educative&logoColor=white&labelColor=blue&messageColor=white)](https://grandpaniuu.github.io/cn-direct-rules/redirect.html?url=shadowrocket%3A%2F%2Finstall%3Fmodule%3Dhttps%3A%2F%2Fraw.githubusercontent.com%2FGrandpaNiuu%2Fcn-direct-rules%2Fmain%2Fdist%2Fshadowrocket%2Fcn-direct.sgmodule "一键安装独立完整模块")
[![查看模块源码](https://img.shields.io/static/v1?label=查看文件&message=cn-direct.sgmodule&color=grey&logo=todoist&logoColor=white&labelColor=%2325A162&messageColor=white)](https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/shadowrocket/cn-direct.sgmodule "查看独立完整模块")

这是一个独立安装的完整模块：包含最大覆盖域名、全部已验证公网 IPv4/IPv6、ASN 与 `GEOIP,CN`。它只向现有 Shadowrocket 配置加入 `[Rule]`，不会冒充完整配置覆盖你的节点、代理组、DNS 或最终策略。请在安装 Shadowrocket 的 iPhone/iPad 上使用 Safari 点击按钮；若系统没有自动唤起 App，可在跳转页点击“打开 Shadowrocket”。

按钮形式参考 [LOWERTOP/Shadowrocket-First](https://github.com/LOWERTOP/Shadowrocket-First)；本仓跳转页为独立实现，并只允许跳转到上方固定模块地址，不能被用作任意网址的开放重定向器。

规则刻意遵守以下边界：

- 包含 `DOMAIN-SUFFIX,cn` 与 `GEOIP,CN`
- 保留显式 `IP-CIDR6`
- 不生成 `GEOSITE,cn`
- 不包含局域网、CGNAT、链路本地或其他保留地址
- 不把 `.io`、`.app`、`.ai` 等全球开放顶级域整体设为直连

## 兼容产物

| 产物 | 用途 | 固定地址 |
| --- | --- | --- |
| `cn.conf` | 完整 `[Rule]` 片段，规则内含 `DIRECT` | [Raw](https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/cn.conf) |
| `shadowrocket/cn-direct.sgmodule` | Shadowrocket 独立完整模块，支持上方一键安装 | [Raw](https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/shadowrocket/cn-direct.sgmodule) |
| `cn-max.conf` | 最大覆盖档位，额外包含大陆导向的开放 IDN/TLD | [Raw](https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/cn-max.conf) |
| `cn-domain.conf` | 仅域名规则 | [Raw](https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/cn-domain.conf) |
| `cn-max-domain.conf` | 最大覆盖档位的仅域名规则 | [Raw](https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/cn-max-domain.conf) |
| `cn-ip.conf` | IPv4、IPv6、ASN 与 GeoIP | [Raw](https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/cn-ip.conf) |
| `cn-ipv4.conf` | 仅显式公网 IPv4 | [Raw](https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/cn-ipv4.conf) |
| `cn-ipv6.conf` | 仅显式公网 IPv6 | [Raw](https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/cn-ipv6.conf) |
| `clash/cn.yaml` | Clash、Mihomo、Stash classical rule-provider | [Raw](https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/clash/cn.yaml) |
| `clash/cn-max.yaml` | Clash/Mihomo/Stash 最大覆盖档位 | [Raw](https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/clash/cn-max.yaml) |
| `rule-set/cn.list` | 不嵌入策略的远程规则集 | [Raw](https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/rule-set/cn.list) |
| `rule-set/cn-max.list` | 不嵌入策略的最大覆盖远程规则集 | [Raw](https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/rule-set/cn-max.list) |
| `SHA256SUMS` | 所有发布产物的 SHA-256 | [Raw](https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/SHA256SUMS) |

`cn.conf` 面向接受 Surge 风格 `[Rule]` 语法的客户端，包括以该格式导入规则的 Shadowrocket、Surge 和 Loon。不同客户端的远程规则入口存在差异，请按客户端文档选择“配置片段”或“规则集”。

Clash/Mihomo 示例：

```yaml
rule-providers:
  cn-direct:
    type: http
    behavior: classical
    format: yaml
    path: ./ruleset/cn-direct.yaml
    url: https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/clash/cn.yaml
    interval: 86400

rules:
  - RULE-SET,cn-direct,DIRECT
```

## 自动维护

每天北京时间 00:00，GitHub Actions 会计划执行（GitHub 可能延迟实际启动）：

1. 下载 IPv4/IPv6 和 V2Fly 中国域名上游快照；
2. 拒绝私网、保留地址、重叠网段、无效 CIDR 和异常数量漂移；
3. 与人工域名、关键字和 ASN 合并；
4. 生成所有 `dist/` 产物并运行单元测试；
5. 仅在内容变化时提交；
6. 为每次变化创建带唯一版本标签和 SHA-256 校验清单的 GitHub Release。

自动生成文件不可直接编辑。人工域名变更应修改 `rules/`；自动快照位于 `upstream/`；数据源和数量保护阈值位于 `config/`。严格覆盖档位会过滤容易误伤全球网站的开放顶级域；最大覆盖档位优先覆盖率，误分流风险略高。

## 发布策略

每个通过验证的数据快照只发布一个 GitHub Release；Release 标签由北京时间日期和提交摘要组成。严格/最大覆盖是同一数据快照的覆盖档位，各客户端文件是兼容产物，不再把它们当成彼此竞争的“版本”。Shadowrocket 独立完整模块同样由这一份规则模型生成，不维护第二套手工规则。

本地检查只依赖 Python 3.11+ 标准库：

```bash
python scripts/build.py
python -m unittest discover -s tests -v
python scripts/validate.py
```

## 数据来源与许可

IPv4/IPv6 快照来自 [fernvenue/chn-cidr-list](https://github.com/fernvenue/chn-cidr-list)；自动域名快照来自采用 MIT License 的 [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community)。详见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) 与 [自检说明](docs/SELF_AUDIT.md)。

本仓库的代码和人工规则采用 MIT License。规则只能降低误分流概率，无法保证任何网络、服务或地区在所有时刻均可达。
