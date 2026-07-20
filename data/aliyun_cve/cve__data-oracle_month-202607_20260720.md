# CVE漏洞列表
- 生成时间: 20260720_144301
- 总数量: 10

## 漏洞列表

| CVE ID | 标题 | 严重性 | CVSS | 披露日期 | CWE | 补丁状态 | 利用状态 |
|--------|------|--------|------|----------|-----|---------|----------|
| AVD-2026-47703 | AdGuard 主页：DoQ 到 UDP 状态减少和源端口 Oracle (CVE-2026-477... | MEDIUM | 6.3 | 2026-07-16 | N/A |  |  |
| AVD-2026-15747 | Perl 9.48 之前的 Mojolicious 版本 4.59 向 BREACH 压缩预言机公开... | CRITICAL | 9.1 | 2026-07-15 | N/A |  |  |
| AVD-2026-56296 | Cap-go transfer_app 应用 ID 枚举漏洞(CVE-2026-56296) | MEDIUM | 6.9 | 2026-07-11 | N/A |  |  |
| AVD-2026-44332 | 中危 Fiber：通过 BasicAuth 默认授权程序中的 Timing Oracle 进行用户名... | MEDIUM | 4.8 | 2026-07-09 | N/A |  |  |
| AVD-2026-41516 | OP-TEE：Hisilicon HPRE PKCS#1 v1.5 解密填充 Oracle (CVE... | LOW | 2.5 | 2026-07-07 | N/A |  |  |
| AVD-2026-41515 | OP-TEE：NXP CAAM 驱动程序中的 RSA-OAEP 填充 oracle 可实现明文恢复 ... | LOW | 2.5 | 2026-07-07 | N/A |  |  |
| AVD-2026-41514 | OP-TEE：海思 HPRE 驱动程序中的 RSA-OAEP 填充 oracle 可实现明文恢复 (... | LOW | 2.5 | 2026-07-07 | N/A |  |  |
| AVD-2026-53422 | SFTP REALPATH 路径存在 Oracle 允许在配置的根之外进行文件系统枚举 (CVE-2... | LOW | 2.3 | 2026-07-03 | N/A |  |  |
| AVD-2026-56327 | Capgo public.invite_user_to_org 信息泄露漏洞(CVE-2026-56... | MEDIUM | 5.3 | 2026-07-01 | N/A |  |  |
| AVD-2026-56300 | Capgo - 通过 RPC 函数未经身份验证的 API 密钥有效性和权限 Oracle (CVE-... | HIGH | 7.5 | 2026-07-01 | N/A |  |  |

## 漏洞详情

### AVD-2026-47703

- **标题**: AdGuard 主页：DoQ 到 UDP 状态减少和源端口 Oracle (CVE-2026-47703)
- **严重性**: MEDIUM
- **CVSS评分**: 6.3
- **CVSS向量**: 
- **披露日期**: 2026-07-16
- **补丁状态**: 
- **利用状态**: 

**描述**:
AdGuard Home is a network-wide software for blocking ads and tracking. Prior to 0.107.75, AdGuard Home's client-triggered DoQ forwarding path to a udp:// upstream reduced backend UDP DNS state by producing dns_id=0 or txid=0 and exposed a quoted-port ICMP source-port oracle, weakening DNS response matching for forwarded queries. This issue is fixed in version 0.107.75.

**解决方案**:
建议您更新当前系统或软件至最新版，完成漏洞的修复。

**参考链接**:
- https://github.com/AdguardTeam/AdGuardHome/security/advisories/GHSA-xgx4-4h9w-53pv

---

### AVD-2026-15747

- **标题**: Perl 9.48 之前的 Mojolicious 版本 4.59 向 BREACH 压缩预言机公开了会话 CSRF 令牌的稳定表示形式 (CVE-2026-15747)
- **严重性**: CRITICAL
- **CVSS评分**: 9.1
- **CVSS向量**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
- **披露日期**: 2026-07-15
- **补丁状态**: 
- **利用状态**: 

**描述**:
Mojolicious versions from 4.59 before 9.48 for Perl expose a stable representation of the session CSRF token to a BREACH compression oracle. _csrf_token generates and caches one token per session and returns the same value on every call, and _csrf_field places that value in a hidden `csrf_token` input. When a response carrying the token also echoes attacker-controlled input and is gzip-compressed, the chosen values and the resulting compressed lengths form a BREACH oracle. An attacker able to qu...

**解决方案**:
建议您更新当前系统或软件至最新版，完成漏洞的修复。

**参考链接**:
- http://www.openwall.com/lists/oss-security/2026/07/14/16
- https://github.com/mojolicious/mojo/commit/01921fbbbbeca2d1397e082d4a647f9b84c24e27.patch
- https://metacpan.org/release/SRI/Mojolicious-9.48/changes

---

### AVD-2026-56296

- **标题**: Cap-go transfer_app 应用 ID 枚举漏洞(CVE-2026-56296)
- **严重性**: MEDIUM
- **CVSS评分**: 6.9
- **CVSS向量**: 
- **披露日期**: 2026-07-11
- **补丁状态**: 
- **利用状态**: 

**描述**:
Cap-go 是基于 Supabase/Postgres 与 Capacitor 的开源移动应用热更新控制台，其服务端的 public.transfer_app PostgreSQL 函数对未认证请求暴露了可观测的执行路径，攻击者仅凭发布版 publishable API key 调用即可根据返回错误消息差异逐条枚举受信任的 app_id。 受影响版本中，Cap-go 0 至 12.128.2（npm 包 capgo / 源码仓库 Cap-go/capgo）下 supabase 模式下授予 anon 角色对 public.transfer_app(p_app_id character varying, p_new_org_id uuid) 的执行权限，函数对目标 app_id 不存在时抛 "App not found"、对未授权调用抛 "You are not authorized to transfer this app."，这两条不同的 RAISE EXCEPTION 文本经 Supabase PostgREST 透传给调用方形成可观测差异，叠加无认证上下文校验，匿名攻击者可遍历 ...

**解决方案**:
将组件 capgo 升级至 12.128.2 及以上版本

**参考链接**:
- https://github.com/Cap-go/capgo/security/advisories/GHSA-fmm3-3qcg-85j6
- https://www.vulncheck.com/advisories/cap-go-app-existence-oracle-via-unauthenticated-transfer-app-rpc

---

### AVD-2026-44332

- **标题**: 中危 Fiber：通过 BasicAuth 默认授权程序中的 Timing Oracle 进行用户名枚举 (CVE-2026-44332)
- **严重性**: MEDIUM
- **CVSS评分**: 4.8
- **CVSS向量**: 
- **披露日期**: 2026-07-09
- **补丁状态**: 
- **利用状态**: 

**描述**:
Fiber is an Express inspired web framework written in Go. Prior to 3.3.0, the default Authorizer function in the BasicAuth middleware in middleware/basicauth/config.go uses short-circuit evaluation that skips password hash comparison for non-existent usernames, enabling reliable remote username enumeration through response timing differences. This issue is fixed in version 3.3.0.

**解决方案**:
建议您更新当前系统或软件至最新版，完成漏洞的修复。

**参考链接**:
- https://github.com/gofiber/fiber/commit/c7ac00edd19f9669b1aebbec6e229658baaa059e
- https://github.com/gofiber/fiber/pull/4245
- https://github.com/gofiber/fiber/releases/tag/v3.3.0
- https://github.com/gofiber/fiber/security/advisories/GHSA-g5vh-55hw-rxm8

---

### AVD-2026-41516

- **标题**: OP-TEE：Hisilicon HPRE PKCS#1 v1.5 解密填充 Oracle (CVE-2026-41516)
- **严重性**: LOW
- **CVSS评分**: 2.5
- **CVSS向量**: CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N
- **披露日期**: 2026-07-07
- **补丁状态**: 
- **利用状态**: 

**描述**:
OP-TEE is a Trusted Execution Environment (TEE) designed as companion to a non-secure Linux kernel running on Arm; Cortex-A cores using the TrustZone technology. Starting in version 4.5.0 and prior to version 4.11.0, the RSA PKCS#1 v1.5 decryption implementation in the Hisilicon HPRE crypto driver uses non-constant-time `memcmp()` for label hash verification and has multiple distinguishable error paths. This creates a Bleichenbacher-style padding oracle that allows an attacker to recover RSA PKC...

**解决方案**:
建议您更新当前系统或软件至最新版，完成漏洞的修复。

**参考链接**:
- https://github.com/OP-TEE/optee_os/security/advisories/GHSA-wxp6-8wwr-h4gf

---

### AVD-2026-41515

- **标题**: OP-TEE：NXP CAAM 驱动程序中的 RSA-OAEP 填充 oracle 可实现明文恢复 (CVE-2026-41515)
- **严重性**: LOW
- **CVSS评分**: 2.5
- **CVSS向量**: CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N
- **披露日期**: 2026-07-07
- **补丁状态**: 
- **利用状态**: 

**描述**:
OP-TEE is a Trusted Execution Environment (TEE) designed as companion to a non-secure Linux kernel running on Arm; Cortex-A cores using the TrustZone technology. Starting in version 3.9.0 and prior to version 4.11.0, the RSA-OAEP decryption implementation in the NXP CAAM crypto driver uses non-constant-time `memcmp()` for label hash verification and has multiple distinguishable error paths. This creates a Manger-style padding oracle that allows an attacker to recover RSA-OAEP plaintext with appr...

**解决方案**:
建议您更新当前系统或软件至最新版，完成漏洞的修复。

**参考链接**:
- https://github.com/OP-TEE/optee_os/security/advisories/GHSA-5q45-58r5-cq4g

---

### AVD-2026-41514

- **标题**: OP-TEE：海思 HPRE 驱动程序中的 RSA-OAEP 填充 oracle 可实现明文恢复 (CVE-2026-41514)
- **严重性**: LOW
- **CVSS评分**: 2.5
- **CVSS向量**: CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N
- **披露日期**: 2026-07-07
- **补丁状态**: 
- **利用状态**: 

**描述**:
OP-TEE is a Trusted Execution Environment (TEE) designed as companion to a non-secure Linux kernel running on Arm; Cortex-A cores using the TrustZone technology. Starting in version 4.5.0 and prior to version 4.11.0, the RSA-OAEP decryption implementation in the Hisilicon HPRE crypto driver uses non-constant-time `memcmp()` for label hash verification and has multiple distinguishable error paths. This creates a Manger-style padding oracle that allows an attacker to recover RSA-OAEP plaintext wit...

**解决方案**:
建议您更新当前系统或软件至最新版，完成漏洞的修复。

**参考链接**:
- https://github.com/OP-TEE/optee_os/security/advisories/GHSA-qw4r-9wj9-q23r

---

### AVD-2026-53422

- **标题**: SFTP REALPATH 路径存在 Oracle 允许在配置的根之外进行文件系统枚举 (CVE-2026-53422)
- **严重性**: LOW
- **CVSS评分**: 2.3
- **CVSS向量**: 
- **披露日期**: 2026-07-03
- **补丁状态**: 
- **利用状态**: 

**描述**:
Observable Response Discrepancy vulnerability in Erlang OTP ssh (ssh_sftpd module) allows an authenticated SFTP user to enumerate the existence of files and directories outside the configured root directory. The SSH_FXP_REALPATH handler in ssh_sftpd calls relate_file_name/3 with Canonicalize=false, unlike every other SFTP operation handler. This allows .. components in the requested path to bypass the is_within_root/2 check without being resolved. The un-canonicalized path then enters resolve_sy...

**解决方案**:
建议您更新当前系统或软件至最新版，完成漏洞的修复。

**参考链接**:
- https://cna.erlef.org/cves/CVE-2026-53422.html
- https://github.com/erlang/otp/commit/059e5785ef8c1d423820ca633fb7b37f47645172
- https://github.com/erlang/otp/commit/86622cfaacf57a02c7645d1999f946846b504c94
- https://github.com/erlang/otp/commit/c5a8f50ae68888ff243c5c741a06d2b3a4b48b7a
- https://github.com/erlang/otp/security/advisories/GHSA-h9pw-h5w4-h976

---

### AVD-2026-56327

- **标题**: Capgo public.invite_user_to_org 信息泄露漏洞(CVE-2026-56327)
- **严重性**: MEDIUM
- **CVSS评分**: 5.3
- **CVSS向量**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N
- **披露日期**: 2026-07-01
- **补丁状态**: 
- **利用状态**: 

**描述**:
Capgo 是开源的 Capacitor 应用即时更新和原生构建管理平台,提供后端服务和 CLI 工具。 受影响版本中,public.invite_user_to_org 函数作为 SECURITY DEFINER 函数未正确验证调用者身份,攻击者可通过可发布的 API 密钥调用该函数,根据返回 NO_ORG 或 NO_RIGHTS 的差异判断目标组织 ID 是否存在,从而实施租户枚举攻击。 修复版本中通过在函数入口处调用 get_identity_org_allowed 获取调用者身份并检查是否为空,将组织不存在和权限不足统一返回 NO_RIGHTS,切断了攻击者通过差异响应判断组织存在的攻击路径。

**解决方案**:
将组件 Cap-go/capgo 升级至 12.128.2 及以上版本

**参考链接**:
- https://github.com/Cap-go/capgo/security/advisories/GHSA-35q8-ghfg-vp6m
- https://www.vulncheck.com/advisories/capgo-unauthenticated-organization-existence-oracle-via-public-invite-user-to-org-rpc

---

### AVD-2026-56300

- **标题**: Capgo - 通过 RPC 函数未经身份验证的 API 密钥有效性和权限 Oracle (CVE-2026-56300)
- **严重性**: HIGH
- **CVSS评分**: 7.5
- **CVSS向量**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
- **披露日期**: 2026-07-01
- **补丁状态**: 
- **利用状态**: 

**描述**:
Capgo before 12.128.2 contains unauthenticated security definer RPC functions get_user_id and get_org_perm_for_apikey that expose API key validity oracles and user UUID disclosure. Unauthenticated attackers using the public API key can validate leaked keys, enumerate users and apps, and determine permission levels, significantly increasing the actionability of compromised credentials.

**解决方案**:
建议您更新当前系统或软件至最新版，完成漏洞的修复。

**参考链接**:
- https://github.com/Cap-go/capgo/security/advisories/GHSA-7r6g-whg3-5mm4
- https://www.vulncheck.com/advisories/capgo-unauthenticated-api-key-validity-and-permission-oracle-via-rpc-functions

---

