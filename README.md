# 🇨🇳 CN Direct Rules

一套每天自动更新的中国大陆直连规则。简单说：国内网站尽量直连，其他流量继续走你原来的代理设置。

规则包含域名、IPv4、IPv6、ASN 和 `GEOIP,CN`，不包含局域网规则，也不使用只有部分客户端支持的 `GEOSITE,cn`。

## 🚀 Shadowrocket 安装

下面两种方式选一种就行。拿不准时，请选第一个“安装模块”。

### ✅ 方式一：安装模块（推荐）

[![安装 Shadowrocket 模块](https://img.shields.io/static/v1?label=Shadowrocket&message=安装模块（推荐）&color=1677ff&logo=rocket&logoColor=white)](https://grandpaniuu.github.io/cn-direct-rules/redirect.html?url=shadowrocket%3A%2F%2Finstall%3Fmodule%3Dhttps%3A%2F%2Fraw.githubusercontent.com%2FGrandpaNiuu%2Fcn-direct-rules%2Fmain%2Fdist%2Fshadowrocket%2Fcn-direct.sgmodule)
[![查看模块文件](https://img.shields.io/static/v1?label=查看&message=模块原始文件&color=25A162)](https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/shadowrocket/cn-direct.sgmodule)

适合已经能正常使用 Shadowrocket、已有节点或订阅的人。它只添加直连规则，不会替换你原来的节点、DNS 和最终代理策略。

1. 在装有 Shadowrocket 的 iPhone 或 iPad 上，用 Safari 打开本页面。
2. 点击上方蓝色“安装模块（推荐）”按钮。
3. 系统询问时，选择“打开 Shadowrocket”。
4. 进入 Shadowrocket 的“模块”，确认 **CN Direct Rules · Complete** 已启用。
5. 全局路由选择“配置”，就可以正常使用了。

### 🧡 方式二：安装完整配置

[![安装 Shadowrocket 配置](https://img.shields.io/static/v1?label=Shadowrocket&message=安装完整配置&color=ed8b00&logo=rocket&logoColor=white)](https://grandpaniuu.github.io/cn-direct-rules/redirect.html?url=shadowrocket%3A%2F%2Fconfig%2Fadd%2Fhttps%3A%2F%2Fraw.githubusercontent.com%2FGrandpaNiuu%2Fcn-direct-rules%2Fmain%2Fdist%2Fshadowrocket%2Fcn-direct.conf)
[![查看配置文件](https://img.shields.io/static/v1?label=查看&message=配置原始文件&color=25A162)](https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/shadowrocket/cn-direct.conf)

适合第一次配置或想换成一份完整规则配置的人。

> ⚠️ 完整配置会替换当前使用的配置。请先备份旧配置，并确认 Shadowrocket 中已有可用节点或订阅。只想增加规则、不想动原配置，请安装上面的模块。

1. 先在 Shadowrocket 中备份旧配置。
2. 点击橙色“安装完整配置”按钮并允许打开 Shadowrocket。
3. 在配置列表中选中新加入的配置。
4. 选择一个可用节点，把全局路由设为“配置”。

## 🔄 打开自动更新

仓库每天北京时间 **00:00** 自动检查上游，并更新固定的 Raw 地址。GitHub 偶尔可能晚几分钟开始，这是正常现象。

想让手机里的规则也自动跟上，请再完成两项设置（不同版本的文字可能略有区别）：

1. iPhone/iPad：`设置 → 通用 → 后台 App 刷新 → Shadowrocket`，打开开关。
2. Shadowrocket：`设置 → 自动更新`，打开“模块”或“配置”的后台更新，并把间隔设为 1 天。

如果某次下载失败，不用慌：手机会继续使用已经安装的规则；仓库会自动重试、切换镜像、合并可安全修复的重复或重叠网段。来源仍不可信时，会保留上一份验证通过的规则，等下一次任务继续尝试，不会硬塞一份可能有问题的数据。

## 🧯 更新失败时怎么做

1. 先确认网络正常，并尝试打开上方“查看原始文件”。
2. 模块用户：进入“模块”页面刷新；仍失败时，重新点击安装模块按钮。
3. 配置用户：在配置详情中选择“更新配置”；仍失败时，重新点击安装完整配置按钮。
4. GitHub 暂时无法访问时，先继续使用现有规则，稍后再试即可。

## 🛡️ 里面有什么规则

- ✅ 中国大陆域名规则，包括 `DOMAIN-SUFFIX,cn`
- ✅ 已验证的中国大陆公网 IPv4 与 IPv6
- ✅ 主要中国大陆 ASN
- ✅ `GEOIP,CN` 兜底
- ❌ 不含局域网、CGNAT、回环、链路本地等地址
- ❌ 不含 `GEOSITE,cn`
- ❌ 不会把 `.io`、`.app`、`.ai` 等全球开放后缀全部强制直连

## 📦 其他客户端与文件

只使用 Shadowrocket 的普通用户，到这里就够了。下面是给其他客户端或进阶用户准备的固定地址。

| 文件 | 用途 | 固定地址 |
| --- | --- | --- |
| `cn.conf` | 完整 `[Rule]` 片段，规则内含 `DIRECT` | [Raw](https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/cn.conf) |
| `shadowrocket/cn-direct.sgmodule` | Shadowrocket 独立完整模块 | [Raw](https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/shadowrocket/cn-direct.sgmodule) |
| `shadowrocket/cn-direct.conf` | Shadowrocket 可远程更新的完整配置 | [Raw](https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/shadowrocket/cn-direct.conf) |
| `cn-max.conf` | 最大覆盖档位，额外包含大陆导向的开放 IDN/TLD | [Raw](https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/cn-max.conf) |
| `cn-domain.conf` | 仅域名规则 | [Raw](https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/cn-domain.conf) |
| `cn-max-domain.conf` | 最大覆盖档位的仅域名规则 | [Raw](https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/cn-max-domain.conf) |
| `cn-ip.conf` | IPv4、IPv6、ASN 与 GeoIP | [Raw](https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/cn-ip.conf) |
| `cn-ipv4.conf` | 仅公网 IPv4 | [Raw](https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/cn-ipv4.conf) |
| `cn-ipv6.conf` | 仅公网 IPv6 | [Raw](https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/cn-ipv6.conf) |
| `clash/cn.yaml` | Clash、Mihomo、Stash classical rule-provider | [Raw](https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/clash/cn.yaml) |
| `clash/cn-max.yaml` | Clash/Mihomo/Stash 最大覆盖档位 | [Raw](https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/clash/cn-max.yaml) |
| `rule-set/cn.list` | 不带固定策略的远程规则集 | [Raw](https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/rule-set/cn.list) |
| `rule-set/cn-max.list` | 不带固定策略的最大覆盖远程规则集 | [Raw](https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/rule-set/cn-max.list) |
| `SHA256SUMS` | 所有发布文件的 SHA-256 | [Raw](https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/SHA256SUMS) |

<details>
<summary>⚙️ 给维护者看的自动化说明</summary>

每天的 GitHub Actions 会：拉取多个上游 → 安全规范化 → 构建全部 `dist/` 文件 → 运行测试与校验 → 仅在内容变化时提交到 `main`。

自动化不会创建 GitHub Release，也不会创建版本 tag。所有订阅始终使用 `main/dist/` 下不变的 Raw 地址。`manifest.json` 记录数据数量和来源摘要，`SHA256SUMS` 覆盖所有发布文件。

本地检查：

```bash
python scripts/build.py
python -m unittest discover -s tests -v
python scripts/validate.py
```

</details>

## 🙏 数据来源与说明

IPv4/IPv6 快照来自 [fernvenue/chn-cidr-list](https://github.com/fernvenue/chn-cidr-list)，域名数据来自采用 MIT License 的 [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community)。安装按钮形式参考 [LOWERTOP/Shadowrocket-First](https://github.com/LOWERTOP/Shadowrocket-First)。

详细信息见 [第三方许可](THIRD_PARTY_NOTICES.md) 与 [自检说明](docs/SELF_AUDIT.md)。仓库代码和人工规则采用 MIT License。规则只能降低误分流概率，无法保证所有网络、服务或地区在任何时刻都可用。
