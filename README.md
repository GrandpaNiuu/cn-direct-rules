# 🇨🇳 CN Direct Rules

一套每天自动更新的中国大陆直连规则超级合集。简单说：把多个可靠项目里的中国域名、IP 和 ASN 自动收集到一起，国内流量尽量直连，其他流量继续走你原来的代理设置。

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

如果某次下载失败，不用慌：手机会继续使用已经安装的规则；仓库会自动重试和切换镜像。某一个来源失败时，只保留它上一次验证通过的数据，其他正常来源仍可更新。

### 🧹 失效规则会怎样处理？

- 一条域名或 ASN 在上游消失一次，不会马上删除，避免把临时故障当成永久失效。
- 只有连续 **3 次不同且成功的上游更新** 都找不到它，才允许自动退役。
- 如果一次准备删除超过 1% 或 1000 条，保护开关会拦住整次更新，继续使用旧规则。
- IP 数量、覆盖范围突然大幅缩水，也会被拦住。
- 已被标记为“不进入主规则”的审计来源，以及 Google/广告/统计等高风险域名根，不走等待期，会在每日更新里直接从主订阅清掉。
- 父域名已经覆盖的子域名会自动去重，例如已有 `DOMAIN-SUFFIX,cn` 时，不再重复保留 `example.cn` 这类子后缀。

这里不会用“某台机器打不开网站”作为删除依据，因为临时维护、DNS、地区网络和 CDN 都可能造成误判。每次处理结果都写在 [`upstream/update-report.json`](upstream/update-report.json)，可以查到新增、等待确认和已退役的数量。

## 🧯 更新失败时怎么做

1. 先确认网络正常，并尝试打开上方“查看原始文件”。
2. 模块用户：进入“模块”页面刷新；仍失败时，重新点击安装模块按钮。
3. 配置用户：在配置详情中选择“更新配置”；仍失败时，重新点击安装完整配置按钮。
4. GitHub 暂时无法访问时，先继续使用现有规则，稍后再试即可。

## 🛡️ 里面有什么规则

- ✅ 11.2 万级中国大陆导向域名规则，包括大陆 DNS 路由、Apple 中国专项域名和 `DOMAIN-SUFFIX,cn`
- ✅ 多路 APNIC/BGP 交叉验证的中国大陆公网 IPv4 与 IPv6
- ✅ 每日维护的中国 ASN 清单
- ✅ 电信、移动、联通、教育网和科技网独立运营商文件
- ✅ APNIC 官方 CN 初始分配文件与覆盖审计
- ✅ `GEOIP,CN` 兜底
- ❌ 不含局域网、CGNAT、回环、链路本地等地址
- ❌ 不含 `GEOSITE,cn`
- ❌ 不会把 `.io`、`.app`、`.ai` 等全球开放后缀全部强制直连
- ❌ 不会把 Google、广告、统计等高风险平台域名塞进主订阅；相关上游只保留来源快照用于审计

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
| `operators/chinanet.conf` | 中国电信 IPv4/IPv6 | [Raw](https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/operators/chinanet.conf) |
| `operators/cmcc.conf` | 中国移动 IPv4/IPv6 | [Raw](https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/operators/cmcc.conf) |
| `operators/unicom.conf` | 中国联通 IPv4/IPv6 | [Raw](https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/operators/unicom.conf) |
| `operators/cernet.conf` | 中国教育网 IPv4/IPv6 | [Raw](https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/operators/cernet.conf) |
| `operators/cstnet.conf` | 中国科技网 IPv4/IPv6 | [Raw](https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/operators/cstnet.conf) |
| `registry/cn-allocated.conf` | APNIC 登记为 CN 的初始分配；不等同实时地理位置 | [Raw](https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/registry/cn-allocated.conf) |
| `SHA256SUMS` | 所有发布文件的 SHA-256 | [Raw](https://raw.githubusercontent.com/GrandpaNiuu/cn-direct-rules/main/dist/SHA256SUMS) |

<details>
<summary>⚙️ 给维护者看的自动化说明</summary>

每天的 GitHub Actions 会：分别拉取多个上游 → 校验来源、格式、数量与覆盖变化 → 去重并合并 → 过滤审计-only 来源和高风险域名 → 自动修复父子域名冗余 → 执行连续缺失退役与大删除保护 → 构建全部 `dist/` 文件 → 运行测试与校验 → 仅在内容变化时提交到 `main`。

自动化不会创建 GitHub Release，也不会创建版本 tag。所有订阅始终使用 `main/dist/` 下不变的 Raw 地址。`manifest.json` 记录数据数量和来源摘要，`SHA256SUMS` 覆盖所有发布文件。

本地检查：

```bash
python scripts/build.py
python -m unittest discover -s tests -v
python scripts/validate.py
```

</details>

## 🙏 数据来源与说明

本仓库只导入上游真实发布的数据，不凭空编写域名、IP 或 ASN：

- 🌐 结构化中国域名：[v2fly/domain-list-community](https://github.com/v2fly/domain-list-community)
- 🧭 大陆 DNS 路由域名：[felixonmars/dnsmasq-china-list](https://github.com/felixonmars/dnsmasq-china-list)
- 📡 APNIC/BGP 中国公网 IP：[fernvenue/chn-cidr-list](https://github.com/fernvenue/chn-cidr-list)
- 📶 独立 BGP 运营商 IP：[gaoyifan/china-operator-ip](https://github.com/gaoyifan/china-operator-ip)
- ⚡ 每小时 BGP 中国 IPv4：[misakaio/chnroutes2](https://github.com/misakaio/chnroutes2)
- 🏛️ 官方初始分配审计：[APNIC delegated statistics](https://ftp.apnic.net/stats/apnic/delegated-apnic-latest)
- 🛰️ 每日中国 ASN：[missuo/ASN-China](https://github.com/missuo/ASN-China)

安装按钮形式参考 [LOWERTOP/Shadowrocket-First](https://github.com/LOWERTOP/Shadowrocket-First)。二次聚合、来源不清或许可条件不适合本仓库的清单不会为了“看起来更多”而重复加入。

详细信息见 [来源准入策略](docs/SOURCE_POLICY.md)、[数据许可](DATA_LICENSE.md)、[第三方许可](THIRD_PARTY_NOTICES.md) 与 [自检说明](docs/SELF_AUDIT.md)。仓库代码采用 MIT License；包含 chnroutes2 数据的生成规则受 CC BY-SA 4.0 的署名与相同方式共享要求约束。规则只能降低误分流概率，无法保证所有网络、服务或地区在任何时刻都可用。
