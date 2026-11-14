# Lazy-fix rules

以 [Johnshall 的 lazy.conf](https://github.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever) 为基础，生成同一批次的 Shadowrocket 与 Mihomo 分流配置。保留原规则意图，补充国内应用与国服游戏直连，并抽取其广告配置中的域名规则；不使用广告 IP 黑名单，不新增 MITM 或解密证书。

公开仓库只存规则、构建代码与来源记录，不存节点、订阅密钥或设备上的合并文件。

## 固定更新地址

| 用途 | 地址 |
| --- | --- |
| iPhone / Mac Shadowrocket | [lazy-fix.conf](https://xuefengyang-a.github.io/lazy-fix-rules/lazy-fix.conf) |
| `.cfg` 兼容别名，字节完全相同 | [lazy-fix.cfg](https://xuefengyang-a.github.io/lazy-fix-rules/lazy-fix.cfg) |
| Windows Mihomo / Clash Verge Rev | [lazy-fix.yaml](https://xuefengyang-a.github.io/lazy-fix-rules/lazy-fix.yaml) |
| 批次、来源与 SHA-256 | [manifest.json](https://xuefengyang-a.github.io/lazy-fix-rules/manifest.json) |
| 离线验证结果与限制 | [validation.json](https://xuefengyang-a.github.io/lazy-fix-rules/validation.json) |

Raw 备用地址：[Shadowrocket `.conf`](https://raw.githubusercontent.com/xuefengyang-A/lazy-fix-rules/gh-pages/lazy-fix.conf)、[Mihomo `.yaml`](https://raw.githubusercontent.com/xuefengyang-A/lazy-fix-rules/gh-pages/lazy-fix.yaml)。不同网络对这两个域名的连通性可能不同。

Shadowrocket 使用设备已有的节点。Mihomo 配置中的 `PROXY` 组只有 `REJECT` 占位，必须在客户端用**本地私密合并配置**绑定自己的节点；未绑定时，代理流量会被拒绝。不要把节点配置上传到此仓库。

两种格式在一次构建中读取同一份上游快照，并在一个 Git 提交中发布。客户端按各自的刷新设置获取，GitHub 缓存和 Pages 部署也可能造成延迟；这不表示三台设备会同时切换。核对配置头部的 `Lazy-fix batch` 可确认批次。

仓库 **Settings → Pages → Build and deployment → Source** 应设为 **GitHub Actions**。同一次工作流先检查产物、上传 Pages artifact、更新 `gh-pages` 备用分支，再部署同一份 artifact 到 Pages；不依赖机器人推送触发第二个构建。发布目录含 `.nojekyll`，直接提供配置文件。[GitHub 自定义工作流说明](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages)

## 更新与维护

工作流每日 UTC 00:30（台北时间 08:30）尝试重建，也可在 Actions 页面用 **Run workflow** 手动触发。推送构建代码或规则设置到 `main` 也会触发。GitHub 的计划任务可能延迟；构建或校验失败时不会发布。如果最后的 Pages 部署失败，Pages 会保留上一版，而 raw 备用分支可能已更新；切换备用地址时先核对批次。[GitHub 计划任务说明](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule)

`overrides.json` 控制广告开关、优先例外、国内直连域名与 Windows 进程规则。例外先于广告规则；广告规则先于常规分流。修改后由离线测试和输出检查验证，再整体发布。国内登录、支付、游戏和广告拦截仍需在实际设备上检查，规则不能保证消除应用对系统 VPN / TUN 状态的检测。

## 本地构建

使用已有 Ruby、curl 与 Ruby 标准库，不安装额外依赖：

```sh
ruby -e 'Dir["*_test.rb"].sort.each { |p| require File.expand_path(p) }'
ruby build.rb --output dist
```

构建下载公开规则及 GeoIP/ASN 数据，成功后才替换 `dist`。GitHub 原始地址连接失败时可回退到 GitHub 官方 Contents API，实际获取端点记入清单；不使用第三方镜像。如果已有 Mihomo 可执行文件，可通过环境变量 `MIHOMO_BIN` 提供它，追加 `-t` 语法检查；构建不会安装或启动客户端。CI 默认不提供此变量，因此 `validation.json` 会明确记录 Mihomo 检查未执行，不能把离线模型通过当作真实联网验收。

`gh-pages` 只发布配置、批次清单、验证结果、公开规则设置、原始规则快照及许可说明。`data/Country.mmdb`、`data/ASN.mmdb` 仅保留在构建目录，避免大型数据每日进入 Git 历史；清单中的 `geodata.file` 是构建内路径，来源 URL 和校验值仍可追溯。设备使用其客户端管理的 GeoIP 数据，地区判定可能因数据库版本而不同。

Mihomo 使用 Fake-IP 保留域名分流信息，并使用 Windows TUN 设置。它与 Shadowrocket 的 DNS、系统回退时序和进程识别能力不完全相同；`USER-AGENT` / `URL-REGEX` 匹配不会被虚构为 Mihomo 规则，不兼容项列在验证文件中。代理 UDP 443 按原配置的 QUIC 策略拒绝，国内直连 UDP 与其他代理 UDP 不受此项影响。

## 来源与许可

此项目是修改、转换后的配置集合，并非上游作者的官方发行。规则与数据分别保留其来源条款，不以单一许可证替代上游许可；详见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)、[Johnshall 许可声明](Johnshall-CC-BY-SA-4.0.txt) 和 [blackmatrix7 许可文本](blackmatrix7-GPL-2.0.txt)。尤其 AI 规则上游另有个人非商业用途及转载限制，不能把本仓库视为无条件可商用的规则包。
