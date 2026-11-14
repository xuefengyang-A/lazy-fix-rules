# Third-party sources and terms

Lazy-fix changes rule order, adds configurable domestic exceptions and domain-only advertising rules, expands remote lists into a paired snapshot, and translates supported matches into Mihomo syntax. These modifications are not endorsed by the upstream authors. Each build's `manifest.json` records the exact source URL, SHA-256 and capture time; `sources/` contains the captured public rule text.

## Johnshall / Shadowrocket-ADBlock-Rules-Forever

- Source: <https://github.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever>
- Files: `release/lazy.conf` and published `sr_ad_only.conf`.
- License: Creative Commons Attribution-ShareAlike 4.0 International, as stated in the [upstream LICENSE](https://github.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever/blob/release/LICENSE).
- The original license notice is preserved in `Johnshall-CC-BY-SA-4.0.txt`; the full terms are available at <https://creativecommons.org/licenses/by-sa/4.0/legalcode>.

## blackmatrix7 / ios_rule_script

- Source: <https://github.com/blackmatrix7/ios_rule_script>
- Files: rule lists referenced by Johnshall's `lazy.conf`, recorded individually in the build manifest.
- The repository's [LICENSE](https://github.com/blackmatrix7/ios_rule_script/blob/master/LICENSE) is the GNU General Public License, version 2; its original text is preserved in `blackmatrix7-GPL-2.0.txt`.
- The captured rule sources and this project's conversion/build source are provided for inspection and reproduction. Preserve applicable upstream notices when redistributing them.

## iab0x00 / ProxyRules

- Source: <https://github.com/iab0x00/ProxyRules>
- File: `Rule/AI.txt`, when referenced by the base configuration.
- No separate standard LICENSE file was present when this integration was prepared. Its [README](https://github.com/iab0x00/ProxyRules/blob/main/README.md) states that resources are for personal study, research and experimentation; commercial/profit use is forbidden. It also prohibits reposting, sharing or publishing them on domestic Chinese platforms, including social media, blogs, forums and code-hosting sites, and disclaims warranties.
- These restrictions are not replaced by a blanket license for this repository. This is a personal, noncommercial GitHub-hosted configuration; consult the upstream terms before further redistribution or use.

## GeoIP and ASN build data

The builder obtains `country.mmdb` and `GeoLite2-ASN.mmdb` from [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat). That repository's code is GPL-3.0; this does not replace the licenses or attribution requirements of the underlying databases.

Its build workflow obtains Country data from [Loyalsoldier/geoip](https://github.com/Loyalsoldier/geoip) and ASN data from [xishang0128/geoip](https://github.com/xishang0128/geoip). Loyalsoldier documents CC-BY-SA-4.0 and GPL-3.0 components; xishang0128's repository documents CC-BY-SA-4.0. Refer to those projects' README and license files for the components you redistribute.

This product includes GeoLite2 data created by MaxMind, available from [MaxMind](https://www.maxmind.com).

The `gh-pages` publication deliberately excludes both MMDB files. Their source links and build hashes remain in the manifest; `data/` paths in that manifest describe the local build output, not files hosted on the publication branch.

## Scope

This notice identifies sources and preserves their terms; it does not relicense third-party material or grant rights that upstream authors have not granted. Source-specific restrictions still apply to combined and converted outputs. No blanket license is asserted for the entire aggregate.
