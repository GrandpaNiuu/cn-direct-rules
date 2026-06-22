# cn-direct-rules

中国大陆公网直连规则。域名规则由仓库维护，IPv4/IPv6 公网快照每天自动更新、校验、生成并发布。

规则刻意遵守以下边界：

- 包含 `DOMAIN-SUFFIX,cn` 与 `GEOIP,CN`
- 保留显式 `IP-CIDR6`
- 不生成 `GEOSITE,cn`
- 不包含局域网、CGNAT、链路本地或其他保留地址
- 不把 `.io`、`.app`、`.ai` 等全球开放顶级域整体设为直连

## 订阅地址

| 产物 | 用途 | 固定地址 |
| --- | --- | --- |
| `cn.conf` | 完整 `[Rule]` 片段，规则内含 `DIRECT` | [Raw](https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/cn.conf) |
| `cn-domain.conf` | 仅域名规则 | [Raw](https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/cn-domain.conf) |
| `cn-ip.conf` | IPv4、IPv6、ASN 与 GeoIP | [Raw](https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/cn-ip.conf) |
| `cn-ipv4.conf` | 仅显式公网 IPv4 | [Raw](https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/cn-ipv4.conf) |
| `cn-ipv6.conf` | 仅显式公网 IPv6 | [Raw](https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/cn-ipv6.conf) |
| `clash/cn.yaml` | Clash、Mihomo、Stash classical rule-provider | [Raw](https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/clash/cn.yaml) |

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

每天北京时间 04:17，GitHub Actions 会：

1. 下载 IPv4/IPv6 上游快照；
2. 拒绝私网、保留地址、重叠网段、无效 CIDR 和异常数量漂移；
3. 与人工域名、关键字和 ASN 合并；
4. 生成所有 `dist/` 产物并运行单元测试；
5. 仅在内容变化时提交；
6. 为每次变化创建带校验清单的不可变 GitHub Release。

自动生成文件不可直接编辑。域名变更应修改 `rules/`；数据源和数量保护阈值位于 `config/`。

本地检查只依赖 Python 3.11+ 标准库：

```bash
python scripts/build.py
python -m unittest discover -s tests -v
python scripts/validate.py
```

## 数据来源与许可

IPv4/IPv6 快照来自 [fernvenue/chn-cidr-list](https://github.com/fernvenue/chn-cidr-list)，其数据综合 BGP/ASN 与 APNIC 并采用 BSD-3-Clause License。详见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

本仓库的代码和人工规则采用 MIT License。规则只能降低误分流概率，无法保证任何网络、服务或地区在所有时刻均可达。
