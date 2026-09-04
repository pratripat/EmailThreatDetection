# Agent Report: SIH26106 Email Forensics Prototype

## 1. Environment & Data Setup

The project is a flat folder at `/home/pratyush/Documents/puttar/github-ssh/sih` containing the two modules and two sample `.eml` files (no subfolder despite the briefing suggesting one). The `origin_analysis.py` module **crashes on first run** because it needs `data/datacenter_ranges.txt` and `data/vpn_ranges.txt`, which were **absent**. The cited GitHub path in the code (`datacenter/ipv4.txt`, `vpn/ipv4.txt`) is wrong — the repo actually serves these at `output/datacenter/ipv4.txt` and `output/vpn/ipv4.txt` (the legacy `ipv4.txt` also exists but is deprecated). I downloaded the correct files (42,849 datacenter ranges, 10,833 VPN ranges) into `data/`. **This is a real portability bug: the module does not bootstrap its own data, has no error handling for missing files, and points at stale repo paths.**

## 2. What Actually Works (verified output)

**Header forensics — spoofed sample** (`sample_spoofed.eml`):
- Correctly reconstructs 3 relay hops, traces earliest IP to `45.135.232.19`
- Parses SPF=fail / DKIM=none / DMARC=fail from Authentication-Results
- Fires 4 anomalies, **risk score 85/100**: 3 failing-auth flags + display-name impersonation ("PayPal Security Team" from `freehostingnow.net`). This is a genuine, correct catch.

**Header forensics — clean sample** (`sample_clean.eml`):
- 2 relay hops, SPF/DKIM/DMARC all pass, **0/100, zero anomalies**. Correct on a legitimate email.

**Origin analysis — built-in test IPs:**
- `185.220.101.47` → **LOW / VPN=True** (matched `185.220.101.0/24`). Correct — this is the Tor/relay-range IP.
- `45.135.232.19` → **MEDIUM-HIGH, not flagged** (confirmed, see §3)
- `203.0.113.44` → **MEDIUM-HIGH, not flagged** (but this is a reserved doc IP, see §3)

The relay-chain parsing, IP extraction, auth-verdict parsing, display-name spoofing detection, and the basic risk scoring all work as advertised on the two clean synthetic samples.

## 3. Concrete Findings, Limitations & Risks

### A. Confirmed coverage gap: `45.135.232.19` is NOT flagged (false negative)
Confirmed with current dataset — this IP does not appear in either the VPN or datacenter lists. Real risk assessed (not just code-reading): this IP is, in practice, a hosting/datacenter address. The system reports **"MEDIUM-HIGH ... consistent with an ordinary residential/ISP connection"** for it. That is the wrong confidence level for what is very likely VPS/datacenter infrastructure. The output's phrasing ("more likely to reflect genuine sender location") actively implies more certainty than the data warrants. **The module's own disclaimer is buried** — it's honest only in a docstring comment, not in the runtime output the user sees.

### B. Frozen/reserved IPs scored as "residential" (categorization bug)
The clean sample IP `203.0.113.44` is in the RFC 5737 documentation range. Python's `ipaddress` correctly reports it as `is_private=True, is_global=False`. The analyzer treats any non-matching IP as "residential/ISP, MEDIUM-HIGH" without a sanity check for reserved/private/documentation space. A 192.0.2.x or 10.x.x.x internal IP would get the same misleading "residential" verdict. Real mail never legitimately carries these in Received headers.

### C. False positive: brand-impersonation regex fires on legitimate marketing/ESP mail (verified)
Test: `From: "Google Cloud Platform Team" <billing@sending-service.com>` with `spf/dkim/dmarc=pass` → **flagged 40/100 for "Display name impersonates 'google'"**. This is a classic scenario: brand-name in display, mail sent through a legitimate ESP (SendGrid/Mailchimp/AWS SES) whose server domain differs from the brand — completely normal for transactional/marketing mail. The matcher uses a naive `brand in display_name and brand not in domain` substring test with a hardcoded 40-point penalty. The check also only fires on an exact substring in the *display*, so `googlemail.com` correctly avoided the flag (verified) but `sending-service.com` did not. This **would generate a flood of false positives on real-world marketing traffic**.

### D. The module trusts Authentication-Results blindly (verification gap)
It explicitly does NOT re-run SPF/DKIM/DMARC (acknowledged in a comment as a network-at-demo constraint). Tested: an email with `From: victim@gmail.com`, Return-Path from `attacker.net`, and a **forged** `spf=pass; dkim=pass; dmarc=pass` scored only **30/100** (just the domain mismatch) despite being malicious. If the analyzer is ever fed untrusted `.eml` (not a trusted MTA's capture), it accepts the sender's self-stamped auth results at face value. For a forensics tool this is a meaningful gap — real captures are trustworthy, but the module offers no mechanism to distinguish trusted vs. injected Authentication-Results.

### E. Subdomain handling: over-sensitive (verified false positive)
`From: registrar@mail.college.edu` vs `Return-Path: <registrar@college.edu>` → flagged **"MISMATCH ... classic spoofing/BEC indicator", +30**. Subdomain mismatches like `mail.college.edu↔college.edu` are extremely common and legitimate in SPF-relay/alias setups. The comparison is a raw string inequality — it does no registrable-domain normalization (e.g., `publicsuffix`). This is a **high-probability false-positive source** on benign corporate mail.

### F. Soft-fail/neutral auth treated as hard failure (+15)
Tested `spf=softfail` → scored 15/100. Softfail and `neutral` are common and often benign; the code only accepts literal `pass`. Similarly an email with **no Authentication-Results header at all** scores 45-70 purely from "MISSING", and an empty/bare `.eml` file hit **70/100** — yet a truncated or non-email file is not evidence of malice. The scoring weights (a MISMATCH=30, three missing auth = 45, plus header-stripping=25) can stack a bare file to 70-100 with zero actual indicators. There is **no lower bound sanity / evidence threshold**, so low-information inputs get high scores.

### G. Minor robustness
- Malformed Received headers (junk/garbage lines) don't crash — they're tolerated and skipped (verified 3-hop parse with two broken lines). Good.
- Missing headers are handled gracefully (`(no subject)`, `(unknown)`, None). Good.
- Empty file → 70/100 with "header stripping" — see F above.
- No timeout/error handling in `_load_ranges`; a missing file raises `FileNotFoundError` (verified — this is what crashed on first run).

## 4. Does the "Reframe geolocation as anonymization detection" decision hold up?

**Partly — the framing is sound, the implementation is honest-but-incomplete.**

Strength: The *concept* is exactly right and directly supported by the PS text ("correlation with VPN, TOR, open relay... cloud-hosted infrastructure"). It sidesteps the "VPNs defeat geolocation" objection entirely, which is a strong, defensible design narrative for judges.

Gaps worth flagging:
- **No TOR/node detection.** The module references TOR in its docstring but only checks VPN and datacenter lists. Tor exit nodes/public relays are not in these lists, so a genuinely TOR-sourced email would return "residential, MEDIUM-HIGH" — the worst possible miss, and the exact case the PS names.
- **No botnet/open-relay/open-proxy coverage** despite the PS explicitly listing them.
- **No confidence-uncertainty surfacing at runtime.** The honest caveat lives in a docstring, not in the user-facing explanation. The "MEDIUM-HIGH" label for a known-datacenter-but-unlisted IP (45.135.232.19) is the concrete failure of this.
- Single-source dependency: one public GitHub list (which the code also references a stale path for). No fallback, no merge of multiple reputation sources, no IP-intelligence enrichment.

So the reframe is a *good* engineering and narrative choice, but the current implementation only covers ~half of what the PS asks for (VPN + datacenter; missing TOR, botnet, relay indicators) and doesn't convey uncertainty strongly enough.

## 5. Changes Needed for Real-World Email Traffic

1. **Fix data bootstrapping**: correct repo paths, auto-download or bundle the lists, and fail gracefully with a clear message if data is missing.
2. **Implement (or stub + clearly label) actual SPF/DKIM/DMARC reverification** via DNS, or gate trust on whether the `.eml` came from a trusted MTA. Do not accept on-face auth headers as a defense-class feature.
3. **Restrict brand-impersonation span** and lower/layer its score; skip the check when auth passes and only apply when combined with other failures, or require the sending domain to be *unrelated* to the brand using a proper suffix list.
4. **Normalize domains with `publicsuffix`** before mismatch comparison to stop the `mail.college.edu` false positive.
5. **Distinguish verdict nuance**: treat `softfail/neutral` differently from `fail`; don't let "MISSING auth" or "empty file" alone drive scores past a low ceiling.
6. **Add reserved/private/documentation IP handling** so 192.0.2.x/203.0.113.x/10.x.x.x are labeled correctly, not "residential".
7. **Add TOR exit-node and known open-relay/botnet checking** to actually honor the PS language.
8. **Surface confidence honesty in the UI/output**, e.g. always emit "not in known lists — could be residential OR an unlisted VPN/datacenter IP."
9. **Score-weight audit**: weights are additive with no cross-checking; add evidence gating so a single noisy signal can't dominate.

## 6. Bottom Line Assessment

**It is a viable deterministic core — for a controlled demo — but it is NOT yet demo-ready for real/uncontrolled input, and it has one sharp edge a professor will find quickly.**

- The two synthetic samples pass cleanly (85 vs 0), the auth parsing, relay reconstruction, and IP/IP-list wiring demonstrably work. That's a legitimate, GPT-free, rule-based foundation — the core thesis is sound.
- But three specific, easily-demonstrated weaknesses will not survive scrutiny: (a) `45.135.232.19` (the project's *own* "malicious" sample IP) is reported as "residential, MEDIUM-HIGH" — a direct, embarrassing counterexample a judge could pull up; (b) a single legitimate ESP-style email (brand display + third-party sending domain, all auth passing) triggers +40 as a "spoof"; (c) `mail.college.edu` vs `college.edu` triggers +30 "BEC" on benign mail. Both (b) and (c) are false positives on *normal* traffic, which is the worst failure mode for a detection tool.
- **MUST fix before demo:** the coverage/confidence mismatch on unlisted datacenter IPs (#1 above), the subdomain false positive, and the missing-data crash. These are quick, high-impact fixes.
- **Should fix for credibility** (mentioned in §5): TOR/botnet coverage gaps, DNS reverification, and surfacing the uncertainty honestly in output text rather than only in a docstring.

If the fracture points (A, C, E above) are addressed, this is a solid, demonstrable deterministic core that will hold up to the "what does your model actually do without GPT" question. As-is, a critical reviewer could derail the demo with the `45.135.232.19` result or a single legitimate marketing email.
