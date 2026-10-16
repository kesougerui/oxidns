// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Proactive cache prefetch helpers.
//!
//! The `cache` plugin refreshes an entry in the background in two situations:
//!
//! - **Lazy refresh** (`lazy_cache_ttl`): a stale hit triggers an asynchronous
//!   refresh while the stale response is still served.
//! - **Prefetch** (this module): a periodic scan looks for entries that are
//!   still fresh but close to their TTL deadline and refreshes them before the
//!   first client asks again.
//!
//! This module keeps the decision logic and the query rebuild separate from the
//! plugin wiring in `mod.rs` so both stay unit-testable without a running
//! server. Nothing here touches the request hot path: the scanner runs inside
//! the plugin's managed background task and the shared in-flight set in
//! `mod.rs` prevents duplicate refreshes.
//!
//! Configuration surface (see `CacheConfig` in `mod.rs`):
//!
//! - `prefetch`: enable proactive prefetch (default: disabled).
//! - `prefetch_before_expire`: share of the TTL (percent) that may still
//!   remain when an entry becomes eligible, counted back from its deadline
//!   (default: 10, i.e. the last 10% of the TTL).
//! - `prefetch_min_hits`: minimum number of cache hits before a domain is
//!   considered hot enough to prefetch (default: 3).
//! - `prefetch_scan_interval`: seconds between prefetch scans (default: 5).
//!
//! Known limitations, documented on purpose:
//!
//! - ECS-keyed entries are skipped: their query carries a client subnet that is
//!   not recoverable from the cache key digest alone.
//! - Prefetch reuses the ingress template captured from the first request seen
//!   after startup, so client-scoped routing matchers observe that identity.

use std::net::SocketAddr;

use crate::core::context::{DnsContext, RequestMeta};
use crate::proto::{Edns, Message, MessageType};

use super::CacheConfig;
use super::CacheItem;

/// Fallback share of the TTL that must have elapsed before prefetching.
pub(super) const DEFAULT_PREFETCH_BEFORE_EXPIRE_PERCENT: u8 = 10;
/// Fallback minimum hit count for an entry to become prefetch-eligible.
pub(super) const DEFAULT_PREFETCH_MIN_HITS: u32 = 3;
/// Fallback scan interval in seconds.
pub(super) const DEFAULT_PREFETCH_SCAN_INTERVAL: u64 = 5;
/// Upper bound of refreshes started by a single scan.
///
/// Bounds the work and the number of concurrent background refreshes so a large
/// cache cannot stall the scanner; remaining candidates are picked up by the
/// next scan.
pub(super) const PREFETCH_MAX_PER_SCAN: usize = 64;

/// Resolved prefetch settings.
///
/// A cache plugin holds `Option<PrefetchSettings>`: `None` means prefetch is
/// disabled and no scanner task is spawned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PrefetchSettings {
    /// Percentage of the TTL that must have elapsed before refreshing.
    pub(super) before_expire_percent: u8,
    /// Minimum number of hits observed on the entry.
    pub(super) min_hits: u32,
    /// Seconds between scans.
    pub(super) scan_interval_secs: u64,
    /// Maximum refreshes started per scan.
    pub(super) max_per_scan: usize,
}

impl PrefetchSettings {
    /// Resolve settings from the plugin configuration.
    ///
    /// Returns `None` when prefetch is disabled or not configured, which is the
    /// default so existing deployments keep their current behavior.
    pub(super) fn from_config(config: &CacheConfig) -> Option<Self> {
        if !config.prefetch.unwrap_or(false) {
            return None;
        }

        Some(Self {
            before_expire_percent: config
                .prefetch_before_expire
                .unwrap_or(DEFAULT_PREFETCH_BEFORE_EXPIRE_PERCENT),
            min_hits: config
                .prefetch_min_hits
                .unwrap_or(DEFAULT_PREFETCH_MIN_HITS),
            scan_interval_secs: config
                .prefetch_scan_interval
                .unwrap_or(DEFAULT_PREFETCH_SCAN_INTERVAL),
            max_per_scan: PREFETCH_MAX_PER_SCAN,
        })
    }
}

/// Ingress template reused by prefetch queries.
///
/// `DnsContext` is not `Clone` and is rebuilt per request by the server layer,
/// so the scanner captures the parts of the first request that matchers can
/// observe (peer address, server metadata, marks) and rebuilds a context for
/// each prefetch query.
#[derive(Debug, Clone)]
pub(super) struct PrefetchTemplate {
    peer_addr: SocketAddr,
    meta: RequestMeta,
    marks: Vec<u32>,
}

impl PrefetchTemplate {
    /// Capture the reusable ingress state of one live request.
    pub(super) fn from_context(context: &DnsContext) -> Self {
        Self {
            peer_addr: context.peer_addr(),
            meta: context.request_meta().clone(),
            marks: context.marks().iter().copied().collect(),
        }
    }

    /// Build a fresh context carrying `query` and the captured ingress state.
    pub(super) fn context_for(&self, query: Message) -> DnsContext {
        let mut context = DnsContext::new(self.peer_addr, query);
        context.set_request_meta(self.meta.clone());
        let marks = context.marks_mut();
        marks.clear();
        marks.extend(self.marks.iter().copied());
        context
    }
}

/// Whether a fresh cache entry should be refreshed before it expires.
///
/// The entry must be hot enough (`min_hits`), still fresh, and inside the
/// closing `before_expire_percent` share of its TTL — that is, the time left
/// must be at most that percentage of the entry's TTL.
pub(super) fn is_prefetch_eligible(
    item: &CacheItem,
    now_ms: u64,
    settings: &PrefetchSettings,
) -> bool {
    if item.hits() < settings.min_hits {
        return false;
    }

    let fresh_until_ms = item.fresh_until_ms;
    if fresh_until_ms <= now_ms {
        return false;
    }

    let ttl_ms = u64::from(item.ttl).saturating_mul(1000);
    if ttl_ms == 0 {
        return false;
    }

    let remaining_ms = fresh_until_ms - now_ms;
    let eligible_below_ms = ttl_ms.saturating_mul(u64::from(settings.before_expire_percent)) / 100;

    remaining_ms <= eligible_below_ms
}

/// Rebuild the query that produced a cached entry.
///
/// The rebuilt query preserves the DNSSEC OK and checking-disabled bits so the
/// refreshed answer stays equivalent to the cached one. ECS-keyed entries are
/// skipped because their client subnet cannot be recovered from the cache key.
pub(super) fn build_prefetch_query(key: &super::key::CacheKey) -> Option<Message> {
    if key.ecs_scope.is_some() {
        return None;
    }

    let question = key.question()?;
    let mut query = Message::new();
    query.set_message_type(MessageType::Query);
    query.set_recursion_desired(true);
    query.set_checking_disabled(key.cd_bit);
    query.add_question(question);

    if key.do_bit {
        let mut edns = Edns::new();
        edns.set_dnssec_ok(true);
        query.set_edns(edns);
    }

    Some(query)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    use crate::proto::{DNSClass, Name, Question, RData, Rcode, Record, RecordType};

    use super::super::key::EcsScopeDigest;
    use super::*;

    fn test_item(ttl: u32, fresh_until_ms: u64, hits: u32) -> CacheItem {
        let mut response = Message::new();
        response.set_rcode(Rcode::NoError);
        response.add_question(Question::new(
            Name::from_ascii("example.com.").expect("name should parse"),
            RecordType::A,
            DNSClass::IN,
        ));
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").expect("name should parse"),
            ttl,
            RData::A(crate::proto::rdata::A(Ipv4Addr::new(1, 1, 1, 1))),
        ));

        let item = CacheItem::new_validated(response, ttl, fresh_until_ms);
        for _ in 0..hits {
            item.record_hit();
        }
        item
    }

    fn settings(before_expire_percent: u8, min_hits: u32) -> PrefetchSettings {
        PrefetchSettings {
            before_expire_percent,
            min_hits,
            scan_interval_secs: 5,
            max_per_scan: PREFETCH_MAX_PER_SCAN,
        }
    }

    fn test_key(do_bit: bool, cd_bit: bool) -> super::super::key::CacheKey {
        super::super::key::CacheKey {
            domain: "example.com".to_string(),
            record_type: RecordType::A,
            dns_class: DNSClass::IN,
            do_bit,
            cd_bit,
            ecs_scope: None,
        }
    }

    fn base_config() -> CacheConfig {
        CacheConfig {
            size: Some(128),
            lazy_cache_ttl: None,
            dump_file: None,
            dump_interval: None,
            short_circuit: Some(false),
            cache_negative: Some(true),
            max_negative_ttl: Some(300),
            negative_ttl_without_soa: Some(60),
            max_positive_ttl: None,
            min_positive_ttl: None,
            ecs_in_key: None,
            prefetch: None,
            prefetch_before_expire: None,
            prefetch_min_hits: None,
            prefetch_scan_interval: None,
        }
    }

    #[test]
    fn settings_are_disabled_by_default() {
        assert_eq!(PrefetchSettings::from_config(&base_config()), None);
    }

    #[test]
    fn settings_apply_documented_defaults() {
        let mut config = base_config();
        config.prefetch = Some(true);

        let settings = PrefetchSettings::from_config(&config).expect("prefetch should resolve");

        assert_eq!(
            settings.before_expire_percent,
            DEFAULT_PREFETCH_BEFORE_EXPIRE_PERCENT
        );
        assert_eq!(settings.min_hits, DEFAULT_PREFETCH_MIN_HITS);
        assert_eq!(settings.scan_interval_secs, DEFAULT_PREFETCH_SCAN_INTERVAL);
        assert_eq!(settings.max_per_scan, PREFETCH_MAX_PER_SCAN);
    }

    #[test]
    fn entry_below_hit_threshold_is_not_eligible() {
        // Only the last second of a 100s TTL remains, but only 2 hits were seen.
        let item = test_item(100, 100_000, 2);

        assert!(!is_prefetch_eligible(&item, 99_000, &settings(10, 3)));
    }

    #[test]
    fn entry_inside_closing_ttl_share_is_eligible() {
        let item = test_item(100, 100_000, 3);

        // 11s left of a 100s TTL = 11%, still outside the last 10%.
        assert!(!is_prefetch_eligible(&item, 89_000, &settings(10, 3)));
        // 10s left of a 100s TTL = exactly the 10% window, eligible.
        assert!(is_prefetch_eligible(&item, 90_000, &settings(10, 3)));
        // 1s left, still eligible.
        assert!(is_prefetch_eligible(&item, 99_000, &settings(10, 3)));
    }

    #[test]
    fn fresh_entry_far_from_expiry_is_not_eligible() {
        // Only 10% of the TTL has been consumed: nothing to do yet.
        let item = test_item(100, 100_000, 10);

        assert!(!is_prefetch_eligible(&item, 10_000, &settings(10, 3)));
        assert!(!is_prefetch_eligible(&item, 50_000, &settings(10, 3)));
    }

    #[test]
    fn stale_entry_is_not_prefetched() {
        let item = test_item(100, 10_000, 10);

        // 10s in: the entry is still fresh but only 1s of TTL remains.

        assert!(!is_prefetch_eligible(&item, 10_000, &settings(10, 3)));
        assert!(!is_prefetch_eligible(&item, 30_000, &settings(10, 3)));
    }

    #[test]
    fn zero_ttl_entry_is_never_eligible() {
        let item = test_item(0, 10_000, 10);

        assert!(!is_prefetch_eligible(&item, 9_999, &settings(10, 3)));
    }

    #[test]
    fn hit_counter_accumulates_per_entry() {
        let item = test_item(100, 95_000, 0);
        assert_eq!(item.hits(), 0);

        item.record_hit();
        item.record_hit();

        assert_eq!(item.hits(), 2);
    }

    #[test]
    fn query_preserves_dnssec_and_checking_bits() {
        let query = build_prefetch_query(&test_key(true, true)).expect("query should build");

        assert_eq!(query.message_type(), MessageType::Query);
        assert!(query.recursion_desired());
        assert!(query.checking_disabled());
        assert_eq!(query.questions().len(), 1);
        assert_eq!(query.questions()[0].name().normalized(), "example.com");
        assert!(
            query
                .edns()
                .as_ref()
                .is_some_and(|edns| edns.flags().dnssec_ok)
        );
    }

    #[test]
    fn query_without_dnssec_bit_has_no_edns() {
        let query = build_prefetch_query(&test_key(false, false)).expect("query should build");

        assert!(!query.checking_disabled());
        assert!(query.edns().is_none());
    }

    #[test]
    fn ecs_keyed_entry_is_not_prefetched() {
        let mut key = test_key(false, false);
        key.ecs_scope = Some(EcsScopeDigest {
            family: 1,
            source_prefix: 24,
            scope_prefix: 24,
            network_len: 3,
            network: [192, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        });

        assert!(build_prefetch_query(&key).is_none());
    }

    #[test]
    fn template_rebuilds_ingress_and_marks() {
        let mut request = Message::new();
        request.add_question(Question::new(
            Name::from_ascii("example.com.").expect("name should parse"),
            RecordType::A,
            DNSClass::IN,
        ));
        let mut origin = DnsContext::new(
            SocketAddr::from((Ipv4Addr::new(192, 168, 2, 50), 5300)),
            request.clone(),
        );
        origin.marks_mut().insert(7);
        origin.set_request_meta(RequestMeta {
            server_name: Some(Arc::from("dns.example.com")),
            url_path: Some(Arc::from("/dns-query")),
        });

        let template = PrefetchTemplate::from_context(&origin);
        let rebuilt = template.context_for(request);

        assert_eq!(
            rebuilt.peer_addr(),
            SocketAddr::from((Ipv4Addr::new(192, 168, 2, 50), 5300))
        );
        assert_eq!(rebuilt.server_name(), Some("dns.example.com"));
        assert_eq!(rebuilt.url_path(), Some("/dns-query"));
        assert!(rebuilt.marks().contains(&7));
    }
}
