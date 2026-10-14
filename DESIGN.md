# Exposight — Landing Page Design Spec (DESIGN.md)

Source: Google Stitch export "Obsidian Surface" (2026-10-13), cleaned for Exposight.
Visual tokens are taken from the Stitch export. All copy rules below override the Stitch mock:
the mock contained claims the product does not make, and those are listed under "Do not use".

Scope: the public landing page (`templates/landing.html`, `static/css/landing.css`, `static/js/landing.js`).
The dashboard follows the same tokens; its additions are in section 9.

---

## 1. Hard rules (security and honesty)

- Strict CSP stays exactly as it is. No CDN scripts, no Tailwind CDN, no Google Fonts, no inline scripts or styles.
  The Stitch `code.html` uses `cdn.tailwindcss.com` and `fonts.googleapis.com`, so it is **reference only — never copy it in**.
- Fonts are self-hosted woff2 under `static/fonts/` with their OFL licence files.
- Icons: Lucide inline SVG (ISC), as already used in C-UI-1.
- Every sentence on the page must be true of the current code. No invented numbers, customers, logos,
  certifications, testimonials or uptime figures.
- Example data (feed lines, inventory rows, topology nodes) must use reserved example names
  (`example.com`, `api.example.com`, `staging.example.com`, documentation IPs `192.0.2.0/24`, `198.51.100.0/24`)
  and be visibly labelled **"Example"**.
- `prefers-reduced-motion: reduce` disables all animation, tilt and the radar sweep.
- Everything readable and usable with JavaScript off.

---

## 2. Colour tokens

Neutral near-black, no green or warm tint. One accent: electric cyan.

| Token | Value | Use |
|---|---|---|
| `--bg` | `#09090B` | page canvas, radar canvas |
| `--surface-1` | `#0C0D0E` | header, inputs, table header |
| `--surface-2` | `#121316` | cards, panels |
| `--surface-3` | `#18191D` | hover / active rows |
| `--border` | `#27272A` | card and input borders |
| `--border-subtle` | `#1E1F24` | row dividers, grid lines |
| `--text` | `#FAFAFA` | primary text |
| `--text-muted` | `#A1A1AA` | secondary text, metadata |
| `--text-faint` | `#52525B` | placeholders, watermark labels |
| `--accent` | `#22D3EE` | primary CTA, highlighted headline words, radar sweep, active states, focus ring |
| `--accent-hover` | `#06B6D4` | primary CTA hover |
| `--accent-glow` | `rgba(34, 211, 238, 0.25)` | focus / hover halo |

Severity colours (match Exposight's Critical → Info tiers):

| Tier | Text / border | Chip background |
|---|---|---|
| Critical | `#EF4444` | `rgba(239, 68, 68, 0.15)` |
| High | `#F97316` | `rgba(249, 115, 22, 0.15)` |
| Medium | `#F59E0B` | `rgba(245, 158, 11, 0.15)` |
| Low | `#3B82F6` | `rgba(59, 130, 246, 0.15)` |
| Info | `#A1A1AA` | `rgba(161, 161, 170, 0.12)` |
| OK / verified | `#10B981` | `rgba(16, 185, 129, 0.15)` |

Chip border = text colour at 35% opacity.

---

## 3. Typography

| Role | Font | Size / line height | Weight | Tracking |
|---|---|---|---|---|
| Display (hero) desktop | Plus Jakarta Sans | 3rem–4rem / 1.08 | 700 | -0.03em |
| Display mobile | Plus Jakarta Sans | 2.25rem / 2.75rem | 700 | -0.025em |
| Headline lg | Plus Jakarta Sans | 2rem / 2.5rem (mobile 1.5rem / 2rem) | 600 | -0.02em |
| Headline md | Plus Jakarta Sans | 1.25rem / 1.75rem | 600 | -0.015em |
| Body lg | Inter | 1rem / 1.5rem | 400 | -0.005em |
| Body md | Inter | 0.875rem / 1.375rem | 400 | 0 |
| Mono labels | IBM Plex Mono (already self-hosted) | 0.6875rem–0.875rem | 400–500 | 0.02em, uppercase for section labels |

- Fonts to add, self-hosted woff2 with OFL: **Plus Jakarta Sans** (variable or 600/700) and **Inter** (variable or 400/500).
  Keep the existing IBM Plex Mono for monospace instead of adding JetBrains Mono (one fewer download).
- This replaces Space Grotesk from C-UI-1. Remove its woff2 and licence if no longer used.
- Highlight words in headlines use `--accent`.
- Keep total font payload as small as practical (latin subset). State the size in the report.

---

## 4. Shape, spacing, depth

- Radius: inputs, buttons, cards `4px`; panels, banners, modals `8px`; pills and chips `9999px`.
- Spacing on a 4/8 px scale. Container max width ~1200px; gutters 16px mobile, 24px desktop.
- Depth comes from tonal steps and 1px borders, not heavy drop shadows.
- Focus / active: border `--accent` (40–100%) plus `box-shadow: 0 0 12px -2px var(--accent-glow)`.
- Overlay / glass (floating nav): `rgba(9, 9, 11, 0.85)` + `backdrop-filter: blur(8px)` + 1px `--border`.

---

## 5. Components

- **Primary button:** bg `--accent`, text `#09090B`, bold. Hover `--accent-hover` + `0 0 16px rgba(34, 211, 238, 0.35)`.
- **Secondary button:** bg `--surface-2`, border `--border`, text `--text`. Hover: border and text `--accent`.
- **Status pill:** IBM Plex Mono, uppercase, rounded-full, padding `2px 8px`, accent chip colours.
- **Card:** bg `--surface-2`, border `--border`; hover lifts to `--surface-3`, border accent at 60%.
- **Input (decorative domain box in hero):** bg `--surface-1`, border `--border`, mono text, placeholder `--text-faint`.
  It is not a working form; clicking it or the button goes to `/app` (sign in).
- **Table (example inventory):** header `--surface-1`, mono uppercase `--text-muted`; rows on `--bg`, divider `--border-subtle`, hover `--surface-3`; severity chips in last column.
- **Feed panel (example scan feed):** terminal-style window with three dots, mono lines, timestamps, one line tinted Critical.
- **Radar:** concentric rings and grid in `--surface-3`, a rotating conic-gradient sweep in `--accent` (CSS only), 4–6 node dots (one Critical red).
- **Floating pill nav:** fixed bottom-centre, glass style, section links; active item `--accent` background with dark text. Hide or simplify below 480px if it covers content.

---

## 6. Page structure (keep C-UI-1 motion system)

1. **Header:** logo + "Exposight", optional small pill "CT monitoring", nav links, **Sign in** (primary, goes to `/app`).
2. **Hero:** small mono status pill → big headline with one cyan phrase → one true paragraph → decorative domain box + "Sign in to verify & scan" button → three mono trust labels.
   Below: a combined panel with the **radar** (left) and the **example scan feed** (right), labelled "Example".
   Keep C-UI-1's 3D-floating recon-pipeline card if it fits; otherwise move it into section 3.
3. **From apex domain to exposed subdomains:** example topology (apex node `example.com` → subdomains), one highlighted exposure, plus the example inventory table.
4. **How it works (pinned scroll sequence from C-UI-1):** Add domain → Verify via DNS TXT → Scan → Alert.
5. **What a scan checks:** the 5 real stages (discovery, probing, port scan, TLS + header inspection, risk scoring).
6. **Built for the people who answer for the perimeter:** feature cards (change detection, scheduled scans, email alerts, audit log, tenant isolation, roles).
7. **Ownership verification:** "Scan only what you own", the TXT record format, why it matters.
8. **Final CTA:** "Watch the domains you own." + Sign in.
9. **Footer:** product line, Dashboard, Terms & acceptable use, Source code.

Fix the C-UI-1 issue where the pinned "How it works" section can leave a long empty dark area: no section may show more than one viewport of blank space at any scroll position.

---

## 7. Approved copy facts (use these, nothing beyond them)

Verify each against the code before use; if the code says otherwise, the code wins.

- Discovers subdomains from **Certificate Transparency logs** via **crt.sh and CertSpotter**.
- Resolves A and AAAA records.
- Probes **HTTP/HTTPS on ports 80 and 443**; private and loopback addresses are refused; responses capped at 64 KB.
- TCP scan of **16 common ports** (connect + banner read only).
- **TLS certificate** checks (validity, expiry, legacy TLS) and **security headers** (HSTS, CSP, X-Content-Type-Options and others the code checks).
- **Risk scoring Critical → Info**.
- **Scans run only on domains verified by a DNS TXT record** (`_exposight-challenge.<domain>` = `exposight-verify=<token>`), checked against independent public resolvers.
- **Change detection** between scans; **scheduled scans** every 6–720 hours with jitter; **email alerts** to up to 5 recipients per domain.
- **Append-only audit log**; **owner / admin / viewer roles**; another tenant's IDs return 404.
- Invite-only access.

Suggested hero headline (C-UI-1, shorter and true):
**"Know every host you expose."** / **"Scan only what you own."** (cyan)

---

## 8. Do not use (found in the Stitch mock)

- "Google Argon", "Cloudflare", "DigiCert" as CT sources → use **crt.sh and CertSpotter**.
- "Cryptographic ownership verification" → use **"DNS TXT ownership verification"** (a TXT token is not cryptographic proof).
- "Zero false positives", "no noise", or any accuracy claim → not supported (E-1a measured noise).
- "Zero-agent", "real-time", "live ingestion", "continuous" as literal claims → scans are scheduled; use "scheduled" or "on a schedule".
- ASN, BGP, Shodan, multi-cloud, subsidiaries, CVE / CVSS / zero-day, "Request Sensor Access", invented counters (nodes, GB/s, latency, uptime).
- `acme-corp.com` or any real-looking company domain → use `example.com`.

---

## 9. Dashboard additions (C-UI-3, C-UI-4)

The dashboard (`static/css/app.css`) and the error pages use the tokens above, plus:

| Token / value | Use | Why |
|---|---|---|
| `--border-hover: #3F3F46` | input and select border on hover | one step lighter than `--border`, so hover is visible without the accent (cyan stays for focus) |
| `#F87171` | Critical chip **text** | `#EF4444` text on its own chip background over the hover row `#18191D` is 4.0:1, below WCAG AA 4.5:1; `#F87171` is 5.4:1 |
| `#60A5FA` | Low chip **text** | `#3B82F6` is 4.0:1 there; `#60A5FA` is 5.8:1 |

Chip borders and backgrounds keep the section 2 values; only the text of these two tiers is lighter.
All other chip texts pass AA with the section 2 colours (lowest: High `#F97316` at 5.1:1).

- **Error pages** (404, 403, 500 for browser page requests): `templates/error.html`, the dashboard header with the radar logo, one panel with a mono "Error NNN" label, a title, one sentence and links to `/` and `/app`. They never show the path, the error or any request data.
- **Favicon:** `static/favicon.svg`, the radar mark in `--accent` on a `--bg` rounded square.
- **Social image:** `static/og-image.png`, 1200x630, `--bg`, radar mark, "Exposight", the hero lines (second line in `--accent`) and a mono label. No numbers or claims beyond section 7.
