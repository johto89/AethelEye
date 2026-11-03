# Third-party notices

AETHELeye itself is licensed under the **GNU General Public License v3.0**. See [`LICENSE`](LICENSE).

This file lists the third-party projects that AETHELeye references, ports or consumes, together with
the license each project uses and a link to its authoritative license text. The third-party license
texts are not duplicated in this repository.

| Component | License | Used in |
|---|---|---|
| WappalyzerSharp / wappalyzergo | MIT | `AethelEye.Modules/Technology/TechnologyCheck.cs` |
| Go `x/net/html` and `regexp/syntax` portions | BSD-3-Clause | inside WappalyzerSharp |
| Wappalyzer fingerprint data | GPL-3.0 | embedded in WappalyzerSharp |
| RetireSharp / retire.js / ASTronomical | Apache-2.0 | `Technology`, `Source` checks |
| gitleaks | MIT | optional external binary |
| gosearch domain-leak/dorks | GPL-3.0 | `AethelEye.Modules/LeakedAccounts` |
| omnisci3nt | MIT | DNS, RDAP, subdomain and social check reference |
| CMSeeK | GPL-3.0 | CMS detection and version-file reference |
| recon-web | GPL-2.0-or-later | security-header, cookie, sitemap and security.txt reference |
| wafw00f | BSD-3-Clause | WAF signature reference |
| .NET / System.Text.Json | MIT | runtime / BCL |

---

## WappalyzerSharp / wappalyzergo

- Project: WappalyzerSharp, a C# port of wappalyzergo
- Upstream: https://github.com/projectdiscovery/wappalyzergo
- Used in: `AethelEye.Modules/Technology/TechnologyCheck.cs`
- License: **MIT** (Copyright (c) 2021 ProjectDiscovery, Inc.)
- License text: https://github.com/projectdiscovery/wappalyzergo/blob/master/LICENSE

WappalyzerSharp also ports parts of the Go standard library:

- `golang.org/x/net/html` tokenizer
- Go `regexp/syntax`

Those portions are Copyright The Go Authors and use the **BSD-3-Clause** license:
https://go.dev/LICENSE

The embedded fingerprint file `WappalyzerSharp/Data/fingerprints_data.json` comes from
wappalyzergo, which generates it from:

- https://github.com/enthec/webappanalyzer - **GPL-3.0**
- https://github.com/HTTPArchive/wappalyzer - **GPL-3.0**

Because that data is GPL-3.0, review the GPL obligations before redistributing a binary that embeds
it. WappalyzerSharp supports `Wappalyzer.FromFile(..., loadEmbedded: false)` if the data must be
shipped separately.

---

## RetireSharp / retire.js / ASTronomical

- Project: RetireSharp, a C# port of retire.js
- Upstream: https://github.com/RetireJS/retire.js
- Used in:
  - `AethelEye.Modules/Technology/TechnologyCheck.cs`
  - `AethelEye.Modules/Technology/RetireRepositoryStore.cs`
  - `AethelEye.Modules/Source/SourceCheck.cs`
- License: **Apache-2.0**
- Copyright: Erlend Oftedal and contributors; ASTronomical Copyright Erlend Oftedal
- License text: https://github.com/RetireJS/retire.js/blob/master/LICENSE

The Retire repository JSON is downloaded at runtime from the retire.js project and is not bundled
in this repository by default.

---

## gitleaks

- Project: gitleaks
- Upstream: https://github.com/gitleaks/gitleaks
- Used as: optional external executable through `ExternalToolRunner`; no source code is copied.
- License: **MIT** (Copyright (c) 2019 Zachary Rice)
- License text: https://github.com/gitleaks/gitleaks/blob/master/LICENSE

If you redistribute the gitleaks binary with AETHELeye, keep its MIT notice with the binary.

---

## gosearch - domain-leak logic and dorks

- Project: gosearch
- Upstream: https://github.com/ibnaleem/gosearch
- Used in:
  - `AethelEye.Modules/LeakedAccounts/LeakedAccountsCheck.cs`
  - `AethelEye.Modules/LeakedAccounts/DorkBuilder.cs`
- License: **GPL-3.0**
- License text: https://github.com/ibnaleem/gosearch/blob/main/LICENSE

These files are a C# port/adaptation of the domain-leak portions of gosearch. AETHELeye as a whole
is distributed under GPL-3.0, which is compatible with this dependency.

---

## omnisci3nt

- Project: omnisci3nt
- Upstream: https://github.com/spyboy-productions/omnisci3nt
- Used in:
  - `AethelEye.Modules/Recon/DnsReconCheck.cs`
  - `AethelEye.Modules/Recon/RdapCheck.cs`
  - `AethelEye.Modules/Recon/SubdomainCheck.cs`
  - `AethelEye.Modules/Recon/SocialCheck.cs`
- License: **MIT** (Copyright (c) 2023 Spyboy)
- License text: https://github.com/spyboy-productions/omnisci3nt/blob/main/LICENSE

The C# checks adapt the DNS, DMARC, WHOIS/RDAP, subdomain and social-media ideas from omnisci3nt.
No Python code is executed or copied verbatim.

---

## CMSeeK

- Project: CMSeeK
- Upstream: https://github.com/Tuhinshubhra/CMSeeK
- Used in: `AethelEye.Modules/Cms/CmsCheck.cs`
- License: **GPL-3.0**
- License text: https://github.com/Tuhinshubhra/CMSeeK/blob/master/LICENSE

The C# check adapts CMSeeK's detection methods (headers, generator meta, page source, robots.txt and
directory/version files). It does not include CMSeeK's exploitation or brute-force modules.

---

## recon-web

- Project: recon-web
- Upstream: https://github.com/BrunoAFK/recon-web
- Used in:
  - `AethelEye.Modules/Security/SecurityCheck.cs`
  - `AethelEye.Modules/Seo/SitemapCheck.cs`
- License: **GPL-2.0-or-later**
- License text: https://github.com/BrunoAFK/recon-web/blob/main/LICENSE

The C# checks adapt the security-header, HSTS, cookie, sitemap and security.txt ideas from
recon-web. AETHELeye is distributed under GPL-3.0, which is compatible with GPL-2.0-or-later.

---

## wafw00f

- Project: wafw00f
- Upstream: https://github.com/EnableSecurity/wafw00f
- Used in: `AethelEye.Modules/Waf/WafCheck.cs`
- License: **BSD-3-Clause** (Copyright (c) 2009-2026, WAFW00F Developers)
- License text: https://github.com/EnableSecurity/wafw00f/blob/master/LICENSE

The C# signature set is inspired by and adapted from wafw00f's plugin checks. No Python code is
executed or copied.

---

## Microsoft .NET and System.Text.Json

- Project: .NET runtime and base class libraries
- Upstream: https://github.com/dotnet/runtime
- License: **MIT**
- License text: https://github.com/dotnet/runtime/blob/main/LICENSE.TXT

AETHELeye is framework-dependent by default and does not bundle the .NET runtime.
