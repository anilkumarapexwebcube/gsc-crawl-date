# GSC Audit Studio — Web Edition

Two Google Search Console automations, originally Chrome extensions, rebuilt as a single
premium website with a home page and dynamic per-tool pages:

- **Crawl Date Tracker** — bulk-check the last Google crawl date + index status for up to
  100 URLs, with pause/resume/stop and CSV export.
- **GSC Audit Studio** — generate full PPTX audit decks (James / Omega / Neon) from the
  live Search Console API, with a password-gated admin area.

## Run it

```bash
cd website
python -m http.server 8754
# open http://localhost:8754
```

Any static host works (Netlify, GitHub Pages, Nginx, IIS…). OAuth sign-in needs an
`http(s)` origin — `file://` won't work.

## Setup (Audit Studio)

The app runs entirely in the browser — no client secret is used or stored. See
[`website/README.md`](website/README.md) for the full one-time OAuth setup (register your
page's origin under the OAuth client's *Authorized JavaScript origins* and enable the
Search Console API), the admin gate, and the screenshot workflow.
