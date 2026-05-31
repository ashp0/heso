//! The search backend pool interface.
//!
//! Per ADR 0026, every general-web source the verb queries is identified
//! by a closed [`BackendId`] enum and dispatched by the `run_search`
//! orchestrator. The closed enum (rather than `dyn Backend`) keeps the
//! pool object-safe-free and lets the orchestrator `match` on the id;
//! keyed/proxy backends slot in later behind the same id space without
//! touching the orchestrator (the [`BackendId::is_default`] filter is the
//! extension point).
//!
//! `BackendId` is the single source of truth for the wire names that
//! appear in `source`, `engines_used`, and `blocked` — the [`as_str`] /
//! [`parse`] pair below is the only place those strings are spelled.
//!
//! [`as_str`]: BackendId::as_str
//! [`parse`]: BackendId::parse

/// Backend identifiers carried in the `source` field of each result and
/// the top-level `engines_used` / `blocked` arrays. The set is closed:
/// every general-web source the verb can query is one of these. Yandex,
/// Bing, and Google are intentionally absent — they gate scripted callers
/// behind CAPTCHA / active human challenges that conflict with the
/// always-on "never rate-limited" posture, so they are documented as
/// unsupported rather than half-implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum BackendId {
    /// Mojeek — independent crawl + index, scrape-friendly, no key. The
    /// reliable backbone of the result set.
    Mojeek,
    /// Brave Search HTML — independent index, no key for the web UI.
    Brave,
    /// Marginalia — small independent index with a public JSON API.
    Marginalia,
    /// DuckDuckGo HTML endpoint (`html.duckduckgo.com`). Opt-in, NOT in the
    /// default pool: DDG `202`/`403`-throttles scripted callers hard per IP,
    /// so from a normal egress IP it only ever adds a `blocked` row. Request
    /// it explicitly via `--engines ddg` (works from residential/proxied
    /// egress).
    DdgHtml,
    /// DuckDuckGo lite endpoint (`lite.duckduckgo.com`). Opt-in like
    /// [`DdgHtml`](BackendId::DdgHtml); same per-IP gate, lighter table layout.
    DdgLite,
    /// SearXNG — only in the default pool when a base URL is configured.
    SearxNg,
    /// Wikipedia REST `summary` — the knowledge block, not a result
    /// backend; never merged into `results`.
    Wiki,
}

impl BackendId {
    /// The stable wire name carried in JSON. `DdgHtml` keeps the bare
    /// `ddg` name it has always used (so existing `--engines ddg` and the
    /// committed envelope shape are unchanged); the lite endpoint is the
    /// new `ddg-lite`.
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            BackendId::Mojeek => "mojeek",
            BackendId::Brave => "brave",
            BackendId::Marginalia => "marginalia",
            BackendId::DdgHtml => "ddg",
            BackendId::DdgLite => "ddg-lite",
            BackendId::SearxNg => "searxng",
            BackendId::Wiki => "wiki",
        }
    }

    /// Parse a wire name back into a [`BackendId`]. The inverse of
    /// [`as_str`](BackendId::as_str); the two must stay in lockstep.
    pub(crate) fn parse(s: &str) -> Option<BackendId> {
        match s {
            "mojeek" => Some(BackendId::Mojeek),
            "brave" => Some(BackendId::Brave),
            "marginalia" => Some(BackendId::Marginalia),
            "ddg" => Some(BackendId::DdgHtml),
            "ddg-lite" => Some(BackendId::DdgLite),
            "searxng" => Some(BackendId::SearxNg),
            "wiki" => Some(BackendId::Wiki),
            _ => None,
        }
    }

    /// True for a backend in the always-on default sweep. SearXNG is
    /// excluded — it is conditionally default, added by the orchestrator only
    /// when a base URL is configured. The DuckDuckGo endpoints are excluded
    /// too: they need no key, but they `202`/`403`-throttle scripted callers
    /// per IP, so they are opt-in (`--engines ddg,ddg-lite`) rather than
    /// always-on, keeping a normal-egress default search clean. A future
    /// keyed backend (Brave API, Serper, …) likewise returns `false` and
    /// joins only when its key is set, without changing the default sweep.
    pub(crate) fn is_default(&self) -> bool {
        matches!(
            self,
            BackendId::Mojeek | BackendId::Brave | BackendId::Marginalia | BackendId::Wiki
        )
    }
}

/// The always-on default pool, in priority order: independent indexes that
/// fail loud via clean status codes. The DuckDuckGo endpoints are
/// deliberately NOT here — they `202`/`403`-throttle scripted callers per
/// IP, so on a normal egress IP they never returned results and only added
/// a `blocked`/`errors` row to every response, making a working search look
/// broken. They stay reachable opt-in via `--engines ddg,ddg-lite` for
/// residential/proxied egress. SearXNG is appended by the orchestrator only
/// when a base URL is configured, so it is absent here. Wikipedia is the
/// knowledge block and is appended last.
pub(crate) const DEFAULT_POOL: &[BackendId] = &[
    BackendId::Mojeek,
    BackendId::Brave,
    BackendId::Marginalia,
    BackendId::Wiki,
];

/// Human-readable list of supported wire names for error messages, kept
/// next to [`BackendId::parse`] so the two never drift.
pub(crate) const SUPPORTED_NAMES: &str = "mojeek, brave, marginalia, ddg, ddg-lite, searxng, wiki";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_str_and_parse_round_trip() {
        for id in [
            BackendId::Mojeek,
            BackendId::Brave,
            BackendId::Marginalia,
            BackendId::DdgHtml,
            BackendId::DdgLite,
            BackendId::SearxNg,
            BackendId::Wiki,
        ] {
            assert_eq!(BackendId::parse(id.as_str()), Some(id));
        }
    }

    #[test]
    fn ddg_wire_name_stays_bare_ddg() {
        // Back-compat: the HTML endpoint keeps the `ddg` name; only the
        // lite endpoint is the new `ddg-lite`.
        assert_eq!(BackendId::DdgHtml.as_str(), "ddg");
        assert_eq!(BackendId::parse("ddg"), Some(BackendId::DdgHtml));
        assert_eq!(BackendId::parse("ddg-lite"), Some(BackendId::DdgLite));
    }

    #[test]
    fn default_pool_excludes_searxng_and_keyed_backends() {
        assert!(!DEFAULT_POOL.contains(&BackendId::SearxNg));
        for id in DEFAULT_POOL {
            assert!(id.is_default(), "{id:?} in DEFAULT_POOL must be default");
        }
    }

    #[test]
    fn searxng_is_not_unconditionally_default() {
        // SearXNG needs an operator-supplied URL, so `is_default` is false;
        // the orchestrator adds it only when one is configured.
        assert!(!BackendId::SearxNg.is_default());
    }
}
