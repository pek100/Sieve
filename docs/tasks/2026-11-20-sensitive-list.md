# The never-decrypt list, reviewed

Date: 2026-11-20. File: `engine/crates/sieve-filter/data/sensitive.txt`.
Reviewed by a second reviewer, not by the owner. The owner took the Q1 recommendation of `docs/tasks/2026-11-06-tls.md` on 2026-11-20: Sieve's own list decides, and the AdGuard HttpsExclusions fetch stays `enabled: false`.

## What it is

Hosts on this list are never decrypted: their TLS passes through untouched, so Sieve can still block them by name but never reads or changes their pages. A bare entry covers the host and every subdomain, a quoted entry covers that host only. An entry can only add pass-through. The list ships as the compiled seed and is replaced by the signed `list-sensitive` update.

It sits on top of a floor that never decrypts anyway, so the list does not repeat it: the `gov`, `mil`, `bank` and `insurance` TLDs; government suffixes such as gov.uk, gov.il, gouv.fr, gob.es, govt.nz, go.jp, gv.at; EV certificates; servers that ask for a client certificate; hosts where a browser rejected Sieve's certificate (self-healing); and every app that is not a registered browser.

## Counts (entries, not comment lines)

| Category | Before | After |
|---|---|---|
| Banking (US, Canada, UK and Ireland, EU and Nordics, Israel incl. credit card companies, Asia-Pacific) | 66 | 188 |
| Finance (brokerage, credit bureaus, payroll, account aggregators) | in banking | 35 |
| Payments (processors, wallets, cards, 3-D Secure, crypto) | 17 | 52 |
| Health (portals, insurers, telehealth, labs, pharmacies) | 25 | 64 |
| Government, identity and tax outside the floor | 0 | 44 |
| Password managers and authenticators | 10 | 18 |
| Identity providers (sign-in hosts) | 0 | 29 |
| Insurance (US, Europe and UK, Israel) | 0 | 43 |
| Legal and e-signature | 0 | 12 |
| Updates (Windows, Apple, Chrome, Firefox, Linux) | 11 | 29 |
| Certificates (OCSP, CRL, CA) | 0 | 29 |
| Pinning apps | 0 | 10 |
| **Total** | **129** | **553** |

No duplicates, no entry covered by another entry, nothing the parser skips, plain ASCII.

## Twenty notable entries

| Entry | Why |
|---|---|
| `"accounts.google.com"` | Google sign-in, exact host only so google.com ads stay filterable |
| `microsoftonline.com` | Entra ID / Microsoft 365 sign-in; the whole domain is identity, no ads |
| `"login.live.com"` | Personal Microsoft account sign-in, exact host |
| `"appleid.apple.com"`, `"idmsa.apple.com"` | Apple Account sign-in, exact hosts |
| `okta.com` | Every company's Okta tenant is a subdomain |
| `duosecurity.com` | Duo two-factor prompts (api-xxxx.duosecurity.com) |
| `plaid.com` | Bank-linking flows that carry bank credentials |
| `stripe.network` | Stripe's card-entry iframes, beside stripe.com |
| `cardinalcommerce.com` | Visa / 3-D Secure challenge host used at card checkout |
| `isracard.co.il`, `max.co.il`, `cal-online.co.il` | Israel's three card issuers |
| `bankhapoalim.co.il` | Largest Israeli bank (with leumi, discount, mizrahi-tefahot, fibi and the smaller banks) |
| `clalit.co.il` | Israeli HMO, with maccabi4u, meuhedet, leumit |
| `canada.ca`, `gc.ca` | Canadian government and CRA; the floor's labels do not catch them |
| `europa.eu` | EU institutions, incl. EU Login (ecas.ec.europa.eu); no ads anywhere |
| `id.me` | US identity verification used by IRS, SSA and states |
| `bankid.com`, `mitid.dk` | Nordic national e-ID sign-in |
| `docusign.net` | Where DocuSign envelopes are actually signed |
| `mp.microsoft.com` | Windows Update delivery, Store and licensing |
| `lencr.org`, `pki.goog` | Let's Encrypt and Google Trust Services OCSP / CRL |
| `services.mozilla.com` | Firefox Sync, push, and the remote settings that carry CRLite and blocklists |

## Main changes from the old seed

Added: the categories that were missing (identity providers, government outside the floor, insurance, legal, certificates, pinning apps) and wider banking coverage: US regionals and credit unions, Canada, UK high-street banks, the large EU and Nordic banks, Israel's smaller banks and card companies, India. Also fixed reach gaps: `rbcroyalbank.com` (RBC's actual online-banking host), `anz.com.au` (not covered by `anz.com`), `nordea.fi/.se/.dk/.no`, `chase.co.uk`, `lloydsbank.co.uk`, `onlinesbi.sbi`, `boursobank.com`.

Removed:
- `webmd.com`, `mayoclinic.org`: ad-funded health content sites, not portals. Passing them through would only stop Sieve filtering their pages; nothing a user types there is account data. Mayo's patient portal is a candidate below.
- `epic.com`, `unitedhealthgroup.com`: corporate sites. The patient portals are `mychart.com`, `uhc.com`, `myuhc.com`, `optum.com`, which stay or were added.
- `protonpass.com`: not confident it is a real Proton host; Proton Pass lives under `proton.me`, which is listed.

Narrowed or widened:
- `delivery.mp.microsoft.com` became `mp.microsoft.com` (wider but still only Store, licensing and update delivery; Delivery Optimization and licensing hosts were missing).
- `fedoraproject.org` became `mirrors.fedoraproject.org` and `dl.fedoraproject.org` (the wiki and project pages are not sensitive).

Kept on purpose: `goodrx.com` (prescription data; its FTC case was exactly about leaking that), `cvs.com`, `walgreens.com`, `boots.com` (pharmacy accounts, even though most of each site is a shop), `creditkarma.com` (credit reports, though ad-funded), bank corporate domains such as `hsbc.com` and `ing.com` (some sign-in hosts live under them; no ads).

## Deliberately not on the list

- Bare big-platform domains: google.com, microsoft.com, apple.com, amazon.com, facebook.com, live.com, yahoo.com, youtube.com, intuit.com. They serve ads and trackers; only their exact sign-in, payment and update hosts are listed.
- Government already covered by the floor: irs.gov, login.gov, gov.uk, gov.il, gouv.fr, gob.es, gov.it, gv.at, go.jp, gov.au.
- Ad-funded health and finance content: webmd.com, mayoclinic.org, healthline.com, boursorama.com (only its old `clients.` banking host is listed).
- Meta, X/Twitter and similar apps that pin: their domains are ad platforms; they are not browsers, so Sieve does not decrypt their apps anyway.
- AdGuard's HttpsExclusions: not used (the owner's decision table: Sieve writes its own list); the fetch is built and stays disabled.

## Candidates left out for lack of certainty

Owner to confirm the domain before adding: Israeli payment apps Bit, Pepper and PayBox (payboxapp.com?), Diners Israel (diners.co.il?), Israeli processors Cardcom and Pelecard, One Zero bank (onezerobank.com?), Meitav and other Israeli investment houses; Mayo Clinic's patient portal host; mychart.org; itsme (itsme-id.com?); Brave and Opera updater hosts; Hachshara insurance; ancestry.com (DNA data on an ad-funded genealogy site).
