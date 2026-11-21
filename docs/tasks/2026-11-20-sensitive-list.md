# The never-decrypt list, reviewed

Date: 2026-11-20. File: `engine/crates/sieve-filter/data/sensitive.txt`.
Reviewed by a second reviewer, not by the owner. The owner took the Q1 recommendation of `docs/tasks/2026-11-06-tls.md` on 2026-11-20: Sieve's own list decides, and the AdGuard HttpsExclusions fetch stays `enabled: false`.

## What it is

Hosts on this list are never decrypted: their TLS passes through untouched, so Sieve can still block them by name but never reads or changes their pages. A bare entry covers the host and every subdomain, a quoted entry covers that host only. An entry can only add pass-through. The list ships as the compiled seed and is replaced by the signed `list-sensitive` update.

It sits on top of a floor that never decrypts anyway, so the list does not repeat it: the `gov`, `mil`, `bank` and `insurance` TLDs; government suffixes such as gov.uk, gov.il, gouv.fr, gob.es, govt.nz, go.jp, gv.at; EV certificates; servers that ask for a client certificate; hosts where a browser rejected Sieve's certificate (self-healing); and every app that is not a registered browser.

## Counts (entries, not comment lines)

| Category | Before | After |
|---|---|---|
| Banking (US, Canada, UK and Ireland, EU and Nordics, Israel incl. credit card companies, Asia-Pacific) | 66 | 253 |
| Finance (brokerage, credit bureaus, payroll, account aggregators) | in banking | 35 |
| Payments (processors, wallets, cards, 3-D Secure, crypto) | 17 | 53 |
| Health (portals, insurers, telehealth, labs, pharmacies) | 25 | 65 |
| Government, identity and tax outside the floor | 0 | 44 |
| Password managers and authenticators | 10 | 18 |
| Identity providers (sign-in hosts) | 0 | 29 |
| Insurance (US, Europe and UK, Israel) | 0 | 43 |
| Legal and e-signature | 0 | 12 |
| Updates (Windows, Apple, Chrome, Firefox, Linux) | 11 | 29 |
| Certificates (OCSP, CRL, CA) | 0 | 29 |
| Pinning apps | 0 | 10 |
| **Total** | **129** | **620** |

The "After" column includes the two entries added on 2026-11-22 (below).

No duplicates, no entry covered by another entry, nothing the parser skips, plain ASCII. The banking count includes 9 globs (see the review fixes below).

## Review fixes (2026-11-20, same day)

The merge review found online-banking hosts missing: banks whose sign-in runs on a separate domain from the brand. Added 66 entries, removed 1 (553 to 618), all banking:

- **Named by the review:** UK `nwolb.com` (NatWest online banking), `rbsdigital.com` (RBS), `halifax-online.co.uk`; US `citizensbankonline.com`, `synchronybank.com`; Israel `bankleumi.co.il` (Leumi's online banking), `telebank.co.il` (Discount's); Germany's regional Sparkassen and Kreissparkassen by glob (below), `haspa.de`.
- **Found in a second pass over the same countries:** US `citicards.com`, `barclaycardus.com`; Canada `pcfinancial.ca`; UK and Ireland `hsbcnet.com`, `co-operativebank.co.uk`, `smile.co.uk`, `sainsburysbank.co.uk`, `danskebank.co.uk`, `365online.com` (Bank of Ireland); Spain `lacaixa.es` (CaixaBank's sign-in), `unicajabanco.es`, `kutxabank.es`, `ibercaja.es`, `abanca.com`; Belgium `bnpparibasfortis.be`; Germany `norisbank.de`, `santander.de`, `1822direkt.de`, `sskm.de`, `sskduesseldorf.de`, the Sparda banks by glob; France `sg.fr` (Societe Generale's online banking is particuliers.sg.fr); Italy `bnl.it`, `credem.it`, `ing.it`; Portugal `novobanco.pt`, `santander.pt`; Austria `bankaustria.at`; Poland `ipko.pl` (PKO BP's online banking), `pekao24.pl`, `bankmillennium.pl`, `aliorbank.pl`; Nordics `danskebank.fi`, `danskebank.se`, `danskebank.no`, `jyskebank.dk`, `sydbank.dk`, `nykredit.dk`, `lansforsakringar.se`, `sparebank1.no`, `s-pankki.fi`; Australia `stgeorge.com.au`, `ing.com.au`, `macquarie.com.au`, `bendigobank.com.au`; New Zealand (the region was listed, its banks were not) `anz.co.nz`, `asb.co.nz`, `westpac.co.nz`, `bnz.co.nz`, `kiwibank.co.nz`; Japan `rakuten-bank.co.jp`, `jp-bank.japanpost.jp`.
- **Globs:** `sparkasse*.de`, `*.sparkasse*.de`, `*-sparkasse.de` (sparkasse-hannover.de, berliner-sparkasse.de and their www hosts), `ksk-*.de`, `*.ksk-*.de` (Kreissparkassen such as ksk-koeln.de), `sparda-*.de`, `*.sparda-*.de`. The syntax's `*` spans dots, so each glob is anchored on a fixed stem at a label edge: `notsparkasse.de` and `kskkoeln.de` do not match. What a glob can still reach is a host whose owner chose such a label (`sparkasse-x.example.de`): that owner only loses page filtering on their own host, which is the safe direction for this list. Test: `the_seed_globs_reach_regional_banks_and_stop_at_the_stem` in `sieve-engine/src/exclusions/lists.rs`.
- **Removed:** `sparkasse.de`, now covered by the first two globs.

Still not listed for lack of certainty: Kreissparkassen without the `ksk-` stem (kskbb.de and similar), Volksbanken (each on its own domain; `vr.de` is the shared portal), Clydesdale and Yorkshire Bank's old online-banking hosts, India's public-sector banks beyond SBI.

## Added 2026-11-22, after run 9

- `mychart.org`. Run 9 found that www.mychart.com redirects to www.mychart.org, which was not listed, so the page that loaded was decrypted. The owner delegated the call to the orchestrator's recommendation: add it (`docs/tasks/2026-11-06-open-decisions.md`, 2026-11-22). Hospitals' own MyChart sites (mychart.<hospital>.org) are on each hospital's domain and cannot be listed one by one.
- `wallet.google.com`. Same pattern: Google's payment pages moved from pay.google.com (listed) to Google Wallet's site.

A pass over the list for the same pattern (a brand whose sign-in or portal runs on a sibling domain) found the rest already covered: Apple's account.apple.com, Google's myaccount and passwords hosts, Microsoft's login.microsoft.com and login.windows.net, the password managers' regional domains (bitwarden.eu, 1password.ca and .eu), kp.org beside kaiserpermanente.org, myuhc.com and optumrx.com, telebank.co.il, bankleumi.co.il, halifax-online.co.uk, metrobankonline.co.uk, merrilledge.com and ml.com, hl.co.uk, card.apple.com, cash.app beside squareup.com, zellepay.com. Test: `the_seed_holds_where_a_portal_redirects_to` in `sieve-engine/src/exclusions/lists.rs`. Still a candidate for lack of certainty: athenahealth's patient app domain.

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

Owner to confirm the domain before adding: Israeli payment apps Bit, Pepper and PayBox (payboxapp.com?), Diners Israel (diners.co.il?), Israeli processors Cardcom and Pelecard, One Zero bank (onezerobank.com?), Meitav and other Israeli investment houses; Mayo Clinic's patient portal host; itsme (itsme-id.com?); Brave and Opera updater hosts; Hachshara insurance; ancestry.com (DNA data on an ad-funded genealogy site).
