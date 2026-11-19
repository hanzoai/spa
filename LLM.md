# spa

**Org:** hanzoai  ·  **Ecosystem:** hanzo  ·  **Path:** `/Users/a/work/hanzo/hanzoai/spa`
**Origin:** https://github.com/hanzoai/spa.git

## Discovery

This file (`LLM.md`) is the canonical agent-facing readme, and the one that is committed; `CLAUDE.md`, `AGENTS.md` and `GEMINI.md` are local symlinks to it.

## Where to look first

- `README.md` — human-facing overview (if present)
- `package.json` / `Cargo.toml` / `pyproject.toml` / `go.mod` — language & deps
- `.github/workflows/` — CI surface
- `docs/` — extended docs (if present)

## Sibling repos

See the org-level `LLM.md` at `/Users/a/work/hanzo/hanzoai/LLM.md` for the full inventory of sibling repos and inter-repo dependencies.

## License

Dual-licensed `MIT OR Apache-2.0` (`LICENSE-MIT`, `LICENSE-APACHE`), at the
user's option. Relicensed from BSD-3-Clause under HIP-0137 "One License"
(`hanzoai/hips`), which standardises original Hanzo work on the dual
permissive pair. The prior BSD copyright line carries forward unchanged
into `LICENSE-MIT`.

## Lightweight Analytics & Ingress Cooperation (`analytics.go`)

- **Configuration**: Enabled via `SPA_ANALYTICS_ENDPOINT` (or `HANZO_ANALYTICS_ENDPOINT`), optional `SPA_ANALYTICS_API_KEY` (`sk-`), `SPA_ANALYTICS_SITE_ID`, and `SPA_ANALYTICS_BEACON_PATH` (default `/_/beacon`, also accepting `/__spa/beacon`).
- **Zero double-counting with `hanzo/ingress`**:
  - When `X-Hanzo-Analytics-Ingress: 1` is present on an HTML navigation GET, `spa` skips server-side initial `page_view` queueing (since `hanzo/ingress` already recorded it) and injects the lightweight `<1KB` route-change listener with `data-initial-tracked="1"`, emitting `/_/beacon` only on `history.pushState`, `history.replaceState`, and `popstate`.
  - Standalone `spa` deployments (without `X-Hanzo-Analytics-Ingress`) emit one initial server `page_view` and stamp `X-Hanzo-Analytics-Tracked: spa` + `data-initial-tracked="1"` so the browser script does not double-count initial load.
- **Captured fields**: `hostname`, normalized `path`, `referrer`, `utm_source`/`utm_medium`/`utm_campaign`/`utm_term`/`utm_content`, `device` (`mobile`/`tablet`/`desktop`), daily privacy-preserving `sessionId`, and click/cookie attribution IDs (`gclid`, `gbraid`, `wbraid`, `fbclid`, `twclid`, `li_fat_id`, `ttclid`, `_fbp`, `_fbc`, `_ttp`).
