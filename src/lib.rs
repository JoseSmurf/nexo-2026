use serde::{Deserialize, Serialize};

pub mod api;
pub mod audit_store;
pub mod profile;
pub mod telemetry;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Baixa,
    Alta,
    Grave,
    Critica,
}

impl Severity {
    pub fn rank(self) -> u8 {
        match self {
            Severity::Baixa => 0,
            Severity::Alta => 1,
            Severity::Grave => 2,
            Severity::Critica => 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Decision {
    Approved,
    FlaggedForReview {
        rule_id: &'static str,
        reason: &'static str,
        severity: Severity,
        measured: u64,
        threshold: u64,
    },
    Blocked {
        rule_id: &'static str,
        reason: &'static str,
        severity: Severity,
        measured: u64,
        threshold: u64,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TransactionIntent<'a> {
    pub user_id: &'a str,
    pub amount_cents: u64,
    pub is_pep: bool,
    pub has_active_kyc: bool,
    pub timestamp_utc_ms: u64,
    pub risk_bps: u16,
    pub ui_hash_valid: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct EngineConfig {
    pub tz_offset_minutes: i16,
    pub night_start: u8,
    pub night_end: u8,
    pub night_limit_cents: u64,
    pub aml_amount_cents: u64,
    pub aml_risk_bps: u16,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            tz_offset_minutes: -180,
            night_start: 20,
            night_end: 6,
            night_limit_cents: 100_000,
            aml_amount_cents: 5_000_000,
            aml_risk_bps: 9_000,
        }
    }
}

impl<'a> TransactionIntent<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        user_id: &'a str,
        amount_cents: u64,
        is_pep: bool,
        has_active_kyc: bool,
        timestamp_utc_ms: u64,
        server_time_ms: u64,
        risk_bps: u16,
        ui_hash_valid: bool,
    ) -> Result<Self, &'static str> {
        if user_id.trim().is_empty() {
            return Err("REJECTED: empty user_id");
        }
        if amount_cents == 0 {
            return Err("REJECTED: zero amount");
        }
        if risk_bps >= 10_000 {
            return Err("REJECTED: risk >= 100%");
        }

        let max_drift_ms = 5 * 60 * 1000;

        if timestamp_utc_ms > server_time_ms.saturating_add(max_drift_ms) {
            return Err("REJECTED: future timestamp");
        }
        if timestamp_utc_ms < server_time_ms.saturating_sub(max_drift_ms) {
            return Err("REJECTED: replay detected");
        }

        Ok(Self {
            user_id,
            amount_cents,
            is_pep,
            has_active_kyc,
            timestamp_utc_ms,
            risk_bps,
            ui_hash_valid,
        })
    }
}

fn policy_hour(timestamp_utc_ms: u64, offset_minutes: i16) -> u8 {
    let utc_s = (timestamp_utc_ms / 1000) as i64;
    let local_s = utc_s + (offset_minutes as i64 * 60);
    let mut sec_day = local_s % 86_400;
    if sec_day < 0 {
        sec_day += 86_400;
    }
    (sec_day / 3600) as u8
}

fn rule_ui_integrity(tx: &TransactionIntent) -> Decision {
    if !tx.ui_hash_valid {
        Decision::Blocked {
            rule_id: "UI-FRAUD-001",
            reason: "UI integrity verification failed.",
            severity: Severity::Critica,
            measured: 1,
            threshold: 0,
        }
    } else {
        Decision::Approved
    }
}

fn rule_night_limit(tx: &TransactionIntent, cfg: EngineConfig) -> Decision {
    let hour = policy_hour(tx.timestamp_utc_ms, cfg.tz_offset_minutes);
    let is_night = if cfg.night_start <= cfg.night_end {
        hour >= cfg.night_start && hour <= cfg.night_end
    } else {
        hour >= cfg.night_start || hour <= cfg.night_end
    };

    if is_night && tx.amount_cents > cfg.night_limit_cents {
        Decision::Blocked {
            rule_id: "BCB-NIGHT-001",
            reason: "Night transaction limit exceeded.",
            severity: Severity::Grave,
            measured: tx.amount_cents,
            threshold: cfg.night_limit_cents,
        }
    } else {
        Decision::Approved
    }
}

fn rule_aml(tx: &TransactionIntent, cfg: EngineConfig) -> Decision {
    if tx.is_pep && !tx.has_active_kyc {
        return Decision::Blocked {
            rule_id: "KYC-PEP-002",
            reason: "PEP without active KYC.",
            severity: Severity::Grave,
            measured: 1,
            threshold: 0,
        };
    }

    let high_risk = tx.risk_bps >= cfg.aml_risk_bps;
    let high_amount = tx.amount_cents >= cfg.aml_amount_cents;

    if high_risk && high_amount {
        return Decision::Blocked {
            rule_id: "AML-FATF-001",
            reason: "High-risk and high-amount transaction.",
            severity: Severity::Critica,
            measured: tx.amount_cents,
            threshold: cfg.aml_amount_cents,
        };
    }

    if high_risk || high_amount {
        return Decision::FlaggedForReview {
            rule_id: "AML-FATF-REVIEW-001",
            reason: "Transaction requires AML review.",
            severity: Severity::Alta,
            measured: tx.amount_cents,
            threshold: cfg.aml_amount_cents,
        };
    }

    Decision::Approved
}

fn hash_field(h: &mut blake3::Hasher, tag: &[u8], data: &[u8]) {
    h.update(&(tag.len() as u32).to_le_bytes());
    h.update(tag);
    h.update(&(data.len() as u32).to_le_bytes());
    h.update(data);
}

pub fn audit_hash(trace: &[Decision]) -> String {
    let mut h = blake3::Hasher::new();
    hash_field(&mut h, b"schema", b"trace_v4");

    for d in trace {
        match *d {
            Decision::Approved => hash_field(&mut h, b"D:A", &[]),
            Decision::FlaggedForReview {
                rule_id,
                reason,
                severity,
                measured,
                threshold,
            } => {
                hash_field(&mut h, b"D:F", rule_id.as_bytes());
                hash_field(&mut h, b"R", reason.as_bytes());
                h.update(&[severity.rank()]);
                h.update(&measured.to_le_bytes());
                h.update(&threshold.to_le_bytes());
            }
            Decision::Blocked {
                rule_id,
                reason,
                severity,
                measured,
                threshold,
            } => {
                hash_field(&mut h, b"D:B", rule_id.as_bytes());
                hash_field(&mut h, b"R", reason.as_bytes());
                h.update(&[severity.rank()]);
                h.update(&measured.to_le_bytes());
                h.update(&threshold.to_le_bytes());
            }
        }
    }

    h.finalize().to_hex().to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FinalDecision {
    Approved,
    Flagged,
    Blocked,
}

pub fn evaluate(tx: &TransactionIntent) -> (FinalDecision, Vec<Decision>, String) {
    evaluate_with_config(tx, EngineConfig::default())
}

pub fn evaluate_with_config(
    tx: &TransactionIntent,
    cfg: EngineConfig,
) -> (FinalDecision, Vec<Decision>, String) {
    // Contract: trace order is fixed and versioned by audit_hash(schema=trace_v4).
    // Reordering rules here changes forensic hashes and must be treated as breaking.
    let trace = vec![
        rule_ui_integrity(tx),
        rule_night_limit(tx, cfg),
        rule_aml(tx, cfg),
    ];

    let final_decision = if trace.iter().any(|d| matches!(d, Decision::Blocked { .. })) {
        FinalDecision::Blocked
    } else if trace
        .iter()
        .any(|d| matches!(d, Decision::FlaggedForReview { .. }))
    {
        FinalDecision::Flagged
    } else {
        FinalDecision::Approved
    };

    let hash = audit_hash(&trace);
    (final_decision, trace, hash)
}
#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // HELPERS
    // ========================================================================

    fn server_time() -> u64 {
        1_736_986_900_000
    }

    fn cfg_brasil() -> EngineConfig {
        EngineConfig {
            tz_offset_minutes: -180,
            night_start: 20,
            night_end: 6,
            night_limit_cents: 100_000,
            aml_amount_cents: 5_000_000,
            aml_risk_bps: 9_000,
        }
    }

    fn cfg_us() -> EngineConfig {
        EngineConfig {
            tz_offset_minutes: -300,
            night_start: 23,
            night_end: 5,
            night_limit_cents: 500_000,
            aml_amount_cents: 10_000_000,
            aml_risk_bps: 9_000,
        }
    }

    fn cfg_eu() -> EngineConfig {
        EngineConfig {
            tz_offset_minutes: 60,
            night_start: 22,
            night_end: 6,
            night_limit_cents: 300_000,
            aml_amount_cents: 10_000_000,
            aml_risk_bps: 9_000,
        }
    }

    fn cfg_cn() -> EngineConfig {
        EngineConfig {
            tz_offset_minutes: 480,
            night_start: 23,
            night_end: 5,
            night_limit_cents: 400_000,
            aml_amount_cents: 10_000_000,
            aml_risk_bps: 9_000,
        }
    }

    fn cfg_ae() -> EngineConfig {
        EngineConfig {
            tz_offset_minutes: 240,
            night_start: 22,
            night_end: 6,
            night_limit_cents: 300_000,
            aml_amount_cents: 10_000_000,
            aml_risk_bps: 9_000,
        }
    }

    fn night_ts() -> (u64, u64) {
        let st = server_time();
        let one_day_ms = 86_400_000u64;
        let start_of_day = st - (st % one_day_ms);
        let night = start_of_day + 82_800_000; // 23h UTC = 20h local (UTC-3)
        let server = night + 60_000;
        (night, server)
    }

    fn local_hour_minute(timestamp_utc_ms: u64, offset_minutes: i16) -> (u8, u8) {
        let utc_s = (timestamp_utc_ms / 1000) as i64;
        let local_s = utc_s + (offset_minutes as i64 * 60);
        let mut sec_day = local_s % 86_400;
        if sec_day < 0 {
            sec_day += 86_400;
        }
        let hour = (sec_day / 3600) as u8;
        let minute = ((sec_day % 3600) / 60) as u8;
        (hour, minute)
    }

    fn ts_for_local_time(cfg: EngineConfig, target_hour: u8, target_minute: u8) -> (u64, u64) {
        let st = server_time();
        let one_day_ms = 86_400_000u64;
        let start_of_day = st - (st % one_day_ms);

        let ts = (0..1_440u64)
            .map(|m| start_of_day + (m * 60_000))
            .find(|ts_candidate| {
                let (h, m) = local_hour_minute(*ts_candidate, cfg.tz_offset_minutes);
                h == target_hour && m == target_minute
            })
            .expect("could not build local timestamp for requested hour/minute");

        (ts, ts + 60_000)
    }

    fn base_tx() -> TransactionIntent<'static> {
        let st = server_time();
        TransactionIntent::new(
            "user_normal",
            50_000,
            false,
            true,
            st - 60_000,
            st,
            1_000,
            true,
        )
        .unwrap()
    }

    // ========================================================================
    // CONTRATO DO ENGINE — 1 teste dedicado para trace.len()
    // ========================================================================

    #[test]
    fn engine_executes_expected_number_of_rules() {
        let tx = base_tx();
        let (_decision, trace, _hash) = evaluate(&tx);
        assert_eq!(trace.len(), 3);
    }

    // ========================================================================
    // TESTES BÁSICOS
    // ========================================================================

    #[test]
    fn approves_safe_transaction() {
        let tx = base_tx();
        let (decision, trace, _hash) = evaluate(&tx);
        assert_eq!(decision, FinalDecision::Approved);
        assert!(trace.iter().all(|d| matches!(d, Decision::Approved)));
    }

    // ========================================================================
    // TESTES DE UI INTEGRITY
    // ========================================================================

    #[test]
    fn blocks_invalid_ui_hash() {
        let st = server_time();
        let tx = TransactionIntent::new(
            "user_fraud",
            50_000,
            false,
            true,
            st - 60_000,
            st,
            1_000,
            false,
        )
        .unwrap();

        let (decision, trace, _hash) = evaluate(&tx);
        assert_eq!(decision, FinalDecision::Blocked);

        let has_ui_block = trace
            .iter()
            .any(|d| matches!(d, Decision::Blocked { rule_id, .. } if *rule_id == "UI-FRAUD-001"));
        assert!(has_ui_block);
    }

    #[test]
    fn hash_changes_when_ui_hash_changes() {
        let st = server_time();

        // duas tx idênticas, só muda ui_hash_valid
        let tx_valid = TransactionIntent::new(
            "user_normal",
            50_000,
            false,
            true,
            st - 60_000,
            st,
            1_000,
            true,
        )
        .unwrap();

        let tx_invalid = TransactionIntent::new(
            "user_normal",
            50_000,
            false,
            true,
            st - 60_000,
            st,
            1_000,
            false,
        )
        .unwrap();

        let (_d, trace_valid, hash_valid) = evaluate(&tx_valid);
        let (_d, trace_invalid, hash_invalid) = evaluate(&tx_invalid);

        // hash mudou
        assert_ne!(hash_valid, hash_invalid);

        // trace inválido TEM UI-FRAUD-001
        let has_ui = trace_invalid
            .iter()
            .any(|d| matches!(d, Decision::Blocked { rule_id, .. } if *rule_id == "UI-FRAUD-001"));
        assert!(has_ui);

        // trace válido NÃO TEM UI-FRAUD-001
        let no_ui = !trace_valid
            .iter()
            .any(|d| matches!(d, Decision::Blocked { rule_id, .. } if *rule_id == "UI-FRAUD-001"));
        assert!(no_ui);
    }

    // ========================================================================
    // TESTES DE LIMITE NOTURNO
    // ========================================================================

    #[test]
    fn blocks_night_limit_exceeded() {
        let (night, st) = night_ts();
        let tx = TransactionIntent::new("user_night", 200_000, false, true, night, st, 1_000, true)
            .unwrap();

        let (decision, trace, _hash) = evaluate_with_config(&tx, cfg_brasil());
        assert_eq!(decision, FinalDecision::Blocked);

        let has_rule = trace
            .iter()
            .any(|d| matches!(d, Decision::Blocked { rule_id, .. } if *rule_id == "BCB-NIGHT-001"));
        assert!(has_rule);
    }

    #[test]
    fn approves_night_below_limit() {
        let (night, st) = night_ts();
        let tx =
            TransactionIntent::new("user_night_ok", 50_000, false, true, night, st, 1_000, true)
                .unwrap();

        let (decision, trace, _hash) = evaluate_with_config(&tx, cfg_brasil());
        assert_eq!(decision, FinalDecision::Approved);

        // garante que a regra não disparou
        assert!(trace.iter().all(|d| {
            !matches!(d, Decision::Blocked { rule_id, .. } if *rule_id == "BCB-NIGHT-001")
        }));
    }

    #[test]
    fn approves_exactly_at_night_limit() {
        let (night, st) = night_ts();
        let tx = TransactionIntent::new("user_exact", 100_000, false, true, night, st, 1_000, true)
            .unwrap();

        let (decision, trace, _hash) = evaluate_with_config(&tx, cfg_brasil());
        assert_eq!(decision, FinalDecision::Approved);

        // garante que a regra não disparou
        assert!(trace.iter().all(|d| {
            !matches!(d, Decision::Blocked { rule_id, .. } if *rule_id == "BCB-NIGHT-001")
        }));
    }

    #[test]
    fn blocks_one_cent_above_night_limit() {
        let (night, st) = night_ts();
        let tx = TransactionIntent::new(
            "user_one_cent",
            100_001,
            false,
            true,
            night,
            st,
            1_000,
            true,
        )
        .unwrap();

        let (decision, trace, _hash) = evaluate_with_config(&tx, cfg_brasil());
        assert_eq!(decision, FinalDecision::Blocked);

        let has_rule = trace
            .iter()
            .any(|d| matches!(d, Decision::Blocked { rule_id, .. } if *rule_id == "BCB-NIGHT-001"));
        assert!(has_rule);
    }

    #[test]
    fn us_night_400k_is_approved() {
        let cfg = cfg_us();
        let (night, st) = ts_for_local_time(cfg, cfg.night_start, 0);
        let tx =
            TransactionIntent::new("user_us_400k", 400_000, false, true, night, st, 1_000, true)
                .unwrap();

        let (decision, trace, _hash) = evaluate_with_config(&tx, cfg);
        assert_eq!(decision, FinalDecision::Approved);
        assert!(!trace.iter().any(
            |d| matches!(d, Decision::Blocked { rule_id, .. } if *rule_id == "BCB-NIGHT-001")
        ));
    }

    #[test]
    fn us_night_600k_is_blocked() {
        let cfg = cfg_us();
        let (night, st) = ts_for_local_time(cfg, cfg.night_start, 0);
        let tx =
            TransactionIntent::new("user_us_600k", 600_000, false, true, night, st, 1_000, true)
                .unwrap();

        let (decision, trace, _hash) = evaluate_with_config(&tx, cfg);
        assert_eq!(decision, FinalDecision::Blocked);
        assert!(trace.iter().any(
            |d| matches!(d, Decision::Blocked { rule_id, .. } if *rule_id == "BCB-NIGHT-001")
        ));
    }

    #[test]
    fn us_approves_exactly_at_night_limit() {
        let cfg = cfg_us();
        let (night, st) = ts_for_local_time(cfg, cfg.night_start, 0);
        let tx = TransactionIntent::new(
            "user_us_exact",
            500_000,
            false,
            true,
            night,
            st,
            1_000,
            true,
        )
        .unwrap();

        let (decision, trace, _hash) = evaluate_with_config(&tx, cfg);
        assert_eq!(decision, FinalDecision::Approved);

        assert!(trace.iter().all(|d| {
            !matches!(d, Decision::Blocked { rule_id, .. } if *rule_id == "BCB-NIGHT-001")
        }));
    }

    #[test]
    fn us_blocks_one_cent_above_night_limit() {
        let cfg = cfg_us();
        let (night, st) = ts_for_local_time(cfg, cfg.night_start, 0);
        let tx = TransactionIntent::new(
            "user_us_one_cent",
            500_001,
            false,
            true,
            night,
            st,
            1_000,
            true,
        )
        .unwrap();

        let (decision, trace, _hash) = evaluate_with_config(&tx, cfg);
        assert_eq!(decision, FinalDecision::Blocked);

        let has_rule = trace
            .iter()
            .any(|d| matches!(d, Decision::Blocked { rule_id, .. } if *rule_id == "BCB-NIGHT-001"));
        assert!(has_rule);
    }

    #[test]
    fn eu_night_250k_is_approved() {
        let cfg = cfg_eu();
        let (night, st) = ts_for_local_time(cfg, cfg.night_start, 0);
        let tx =
            TransactionIntent::new("user_eu_250k", 250_000, false, true, night, st, 1_000, true)
                .unwrap();

        let (decision, trace, _hash) = evaluate_with_config(&tx, cfg);
        assert_eq!(decision, FinalDecision::Approved);
        assert!(!trace.iter().any(
            |d| matches!(d, Decision::Blocked { rule_id, .. } if *rule_id == "BCB-NIGHT-001")
        ));
    }

    #[test]
    fn eu_night_400k_is_blocked() {
        let cfg = cfg_eu();
        let (night, st) = ts_for_local_time(cfg, cfg.night_start, 0);
        let tx =
            TransactionIntent::new("user_eu_400k", 400_000, false, true, night, st, 1_000, true)
                .unwrap();

        let (decision, trace, _hash) = evaluate_with_config(&tx, cfg);
        assert_eq!(decision, FinalDecision::Blocked);
        assert!(trace.iter().any(
            |d| matches!(d, Decision::Blocked { rule_id, .. } if *rule_id == "BCB-NIGHT-001")
        ));
    }

    #[test]
    fn eu_approves_exactly_at_night_limit() {
        let cfg = cfg_eu();
        let (night, st) = ts_for_local_time(cfg, cfg.night_start, 0);
        let tx = TransactionIntent::new(
            "user_eu_exact",
            300_000,
            false,
            true,
            night,
            st,
            1_000,
            true,
        )
        .unwrap();

        let (decision, trace, _hash) = evaluate_with_config(&tx, cfg);
        assert_eq!(decision, FinalDecision::Approved);

        assert!(trace.iter().all(|d| {
            !matches!(d, Decision::Blocked { rule_id, .. } if *rule_id == "BCB-NIGHT-001")
        }));
    }

    #[test]
    fn eu_blocks_one_cent_above_night_limit() {
        let cfg = cfg_eu();
        let (night, st) = ts_for_local_time(cfg, cfg.night_start, 0);
        let tx = TransactionIntent::new(
            "user_eu_one_cent",
            300_001,
            false,
            true,
            night,
            st,
            1_000,
            true,
        )
        .unwrap();

        let (decision, trace, _hash) = evaluate_with_config(&tx, cfg);
        assert_eq!(decision, FinalDecision::Blocked);

        let has_rule = trace
            .iter()
            .any(|d| matches!(d, Decision::Blocked { rule_id, .. } if *rule_id == "BCB-NIGHT-001"));
        assert!(has_rule);
    }

    #[test]
    fn br_night_400k_is_blocked() {
        let cfg = cfg_brasil();
        let (night, st) = ts_for_local_time(cfg, cfg.night_start, 0);
        let tx =
            TransactionIntent::new("user_br_400k", 400_000, false, true, night, st, 1_000, true)
                .unwrap();

        let (decision, trace, _hash) = evaluate_with_config(&tx, cfg);
        assert_eq!(decision, FinalDecision::Blocked);
        assert!(trace.iter().any(
            |d| matches!(d, Decision::Blocked { rule_id, .. } if *rule_id == "BCB-NIGHT-001")
        ));
    }

    #[test]
    fn cn_night_350k_is_approved() {
        let cfg = cfg_cn();
        let (night, st) = ts_for_local_time(cfg, cfg.night_start, 0);
        let tx =
            TransactionIntent::new("user_cn_350k", 350_000, false, true, night, st, 1_000, true)
                .unwrap();

        let (decision, trace, _hash) = evaluate_with_config(&tx, cfg);
        assert_eq!(decision, FinalDecision::Approved);
        assert!(!trace.iter().any(
            |d| matches!(d, Decision::Blocked { rule_id, .. } if *rule_id == "BCB-NIGHT-001")
        ));
    }

    #[test]
    fn cn_night_450k_is_blocked() {
        let cfg = cfg_cn();
        let (night, st) = ts_for_local_time(cfg, cfg.night_start, 0);
        let tx =
            TransactionIntent::new("user_cn_450k", 450_000, false, true, night, st, 1_000, true)
                .unwrap();

        let (decision, trace, _hash) = evaluate_with_config(&tx, cfg);
        assert_eq!(decision, FinalDecision::Blocked);
        assert!(trace.iter().any(
            |d| matches!(d, Decision::Blocked { rule_id, .. } if *rule_id == "BCB-NIGHT-001")
        ));
    }

    #[test]
    fn cn_approves_exactly_at_night_limit() {
        let cfg = cfg_cn();
        let (night, st) = ts_for_local_time(cfg, cfg.night_start, 0);
        let tx = TransactionIntent::new(
            "user_cn_exact",
            400_000,
            false,
            true,
            night,
            st,
            1_000,
            true,
        )
        .unwrap();

        let (decision, trace, _hash) = evaluate_with_config(&tx, cfg);
        assert_eq!(decision, FinalDecision::Approved);

        assert!(trace.iter().all(|d| {
            !matches!(d, Decision::Blocked { rule_id, .. } if *rule_id == "BCB-NIGHT-001")
        }));
    }

    #[test]
    fn cn_blocks_one_cent_above_night_limit() {
        let cfg = cfg_cn();
        let (night, st) = ts_for_local_time(cfg, cfg.night_start, 0);
        let tx = TransactionIntent::new(
            "user_cn_one_cent",
            400_001,
            false,
            true,
            night,
            st,
            1_000,
            true,
        )
        .unwrap();

        let (decision, trace, _hash) = evaluate_with_config(&tx, cfg);
        assert_eq!(decision, FinalDecision::Blocked);

        let has_rule = trace
            .iter()
            .any(|d| matches!(d, Decision::Blocked { rule_id, .. } if *rule_id == "BCB-NIGHT-001"));
        assert!(has_rule);
    }

    #[test]
    fn ae_approves_below_night_limit() {
        let cfg = cfg_ae();
        let (night, st) = ts_for_local_time(cfg, cfg.night_start, 0);
        let tx =
            TransactionIntent::new("user_ae_200k", 200_000, false, true, night, st, 1_000, true)
                .unwrap();

        let (decision, trace, _hash) = evaluate_with_config(&tx, cfg);
        assert_eq!(decision, FinalDecision::Approved);
        assert!(!trace.iter().any(
            |d| matches!(d, Decision::Blocked { rule_id, .. } if *rule_id == "BCB-NIGHT-001")
        ));
    }

    #[test]
    fn ae_blocks_above_night_limit() {
        let cfg = cfg_ae();
        let (night, st) = ts_for_local_time(cfg, cfg.night_start, 0);
        let tx =
            TransactionIntent::new("user_ae_400k", 400_000, false, true, night, st, 1_000, true)
                .unwrap();

        let (decision, trace, _hash) = evaluate_with_config(&tx, cfg);
        assert_eq!(decision, FinalDecision::Blocked);
        assert!(trace.iter().any(
            |d| matches!(d, Decision::Blocked { rule_id, .. } if *rule_id == "BCB-NIGHT-001")
        ));
    }

    #[test]
    fn ae_approves_exactly_at_night_limit() {
        let cfg = cfg_ae();
        let (night, st) = ts_for_local_time(cfg, cfg.night_start, 0);
        let tx = TransactionIntent::new(
            "user_ae_exact",
            300_000,
            false,
            true,
            night,
            st,
            1_000,
            true,
        )
        .unwrap();

        let (decision, trace, _hash) = evaluate_with_config(&tx, cfg);
        assert_eq!(decision, FinalDecision::Approved);
        assert!(trace.iter().all(|d| {
            !matches!(d, Decision::Blocked { rule_id, .. } if *rule_id == "BCB-NIGHT-001")
        }));
    }

    #[test]
    fn ae_blocks_one_cent_above_night_limit() {
        let cfg = cfg_ae();
        let (night, st) = ts_for_local_time(cfg, cfg.night_start, 0);
        let tx = TransactionIntent::new(
            "user_ae_one_cent",
            300_001,
            false,
            true,
            night,
            st,
            1_000,
            true,
        )
        .unwrap();

        let (decision, trace, _hash) = evaluate_with_config(&tx, cfg);
        assert_eq!(decision, FinalDecision::Blocked);

        let has_rule = trace
            .iter()
            .any(|d| matches!(d, Decision::Blocked { rule_id, .. } if *rule_id == "BCB-NIGHT-001"));
        assert!(has_rule);
    }

    // ========================================================================
    // TESTES AML / KYC / PEP
    // ========================================================================

    #[test]
    fn blocks_pep_without_kyc() {
        let st = server_time();
        let tx = TransactionIntent::new(
            "user_pep",
            50_000,
            true,
            false,
            st - 60_000,
            st,
            1_000,
            true,
        )
        .unwrap();

        let (decision, trace, _hash) = evaluate(&tx);
        assert_eq!(decision, FinalDecision::Blocked);

        let has_pep_block = trace
            .iter()
            .any(|d| matches!(d, Decision::Blocked { rule_id, .. } if *rule_id == "KYC-PEP-002"));
        assert!(has_pep_block);
    }

    #[test]
    fn approves_pep_with_kyc() {
        let st = server_time();
        let tx = TransactionIntent::new(
            "user_pep_ok",
            50_000,
            true,
            true,
            st - 60_000,
            st,
            1_000,
            true,
        )
        .unwrap();

        let (decision, _trace, _hash) = evaluate(&tx);
        assert_eq!(decision, FinalDecision::Approved);
    }

    #[test]
    fn blocks_high_risk_and_high_amount() {
        let st = server_time();
        let tx = TransactionIntent::new(
            "user_aml",
            5_000_000,
            false,
            true,
            st - 60_000,
            st,
            9_000,
            true,
        )
        .unwrap();

        let (decision, trace, _hash) = evaluate(&tx);
        assert_eq!(decision, FinalDecision::Blocked);

        let has_aml_block = trace
            .iter()
            .any(|d| matches!(d, Decision::Blocked { rule_id, .. } if *rule_id == "AML-FATF-001"));
        assert!(has_aml_block);
    }

    #[test]
    fn flags_high_risk_only() {
        let st = server_time();
        let tx = TransactionIntent::new(
            "user_risk",
            50_000,
            false,
            true,
            st - 60_000,
            st,
            9_000,
            true,
        )
        .unwrap();

        let (decision, trace, _hash) = evaluate(&tx);
        assert_eq!(decision, FinalDecision::Flagged);

        let has_review = trace.iter().any(|d| {
            matches!(d, Decision::FlaggedForReview { rule_id, .. } if *rule_id == "AML-FATF-REVIEW-001")
        });
        assert!(has_review);

        // flagged puro: sem blocked
        assert!(!trace.iter().any(|d| matches!(d, Decision::Blocked { .. })));
    }

    #[test]
    fn blocks_high_amount_only() {
        // amount alto sozinho vira FLAGGED na AML, mas aqui o horário também cai na regra noturna.
        let st = server_time();
        let tx = TransactionIntent::new(
            "user_amount",
            5_000_000,
            false,
            true,
            st - 60_000,
            st,
            1_000,
            true,
        )
        .unwrap();

        let (decision, trace, _hash) = evaluate(&tx);
        assert_eq!(decision, FinalDecision::Blocked);

        let has_block_rule = trace
            .iter()
            .any(|d| matches!(d, Decision::Blocked { rule_id, .. } if *rule_id == "BCB-NIGHT-001"));
        assert!(has_block_rule);
    }

    #[test]
    fn flags_high_amount_only_outside_night_window() {
        let cfg = cfg_brasil();
        let (day_ts, st) = ts_for_local_time(cfg, 12, 0);
        let tx = TransactionIntent::new(
            "user_amount_day",
            5_000_000,
            false,
            true,
            day_ts,
            st,
            1_000,
            true,
        )
        .unwrap();

        let (decision, trace, _hash) = evaluate_with_config(&tx, cfg);
        assert_eq!(decision, FinalDecision::Flagged);

        let has_review = trace.iter().any(|d| {
            matches!(d, Decision::FlaggedForReview { rule_id, .. } if *rule_id == "AML-FATF-REVIEW-001")
        });
        assert!(has_review);
        assert!(!trace.iter().any(|d| matches!(d, Decision::Blocked { .. })));
    }

    #[test]
    fn approves_low_risk_low_amount() {
        let st = server_time();
        let tx = TransactionIntent::new(
            "user_safe",
            50_000,
            false,
            true,
            st - 60_000,
            st,
            1_000,
            true,
        )
        .unwrap();

        let (decision, _trace, _hash) = evaluate(&tx);
        assert_eq!(decision, FinalDecision::Approved);
    }

    #[test]
    fn approves_aml_near_risk_limit_without_night_block() {
        let cfg = cfg_brasil();
        let (day_ts, st) = ts_for_local_time(cfg, 12, 0);
        let tx = TransactionIntent::new(
            "user_near_risk",
            50_000,
            false,
            true,
            day_ts,
            st,
            8_999,
            true,
        )
        .unwrap();

        let (decision, trace, _hash) = evaluate_with_config(&tx, cfg);
        assert_eq!(decision, FinalDecision::Approved);
        assert!(!trace
            .iter()
            .any(|d| matches!(d, Decision::FlaggedForReview { rule_id, .. } if *rule_id == "AML-FATF-REVIEW-001")));
    }

    #[test]
    fn approves_aml_near_amount_limit_without_night_block() {
        let cfg = cfg_brasil();
        let (day_ts, st) = ts_for_local_time(cfg, 12, 0);
        let tx = TransactionIntent::new(
            "user_near_amount",
            4_999_999,
            false,
            true,
            day_ts,
            st,
            1_000,
            true,
        )
        .unwrap();

        let (decision, trace, _hash) = evaluate_with_config(&tx, cfg);
        assert_eq!(decision, FinalDecision::Approved);
        assert!(!trace
            .iter()
            .any(|d| matches!(d, Decision::FlaggedForReview { rule_id, .. } if *rule_id == "AML-FATF-REVIEW-001")));
    }

    #[test]
    fn approves_non_pep_without_kyc_when_other_signals_are_safe() {
        let cfg = cfg_brasil();
        let (day_ts, st) = ts_for_local_time(cfg, 12, 0);
        let tx = TransactionIntent::new(
            "user_non_pep_no_kyc",
            50_000,
            false,
            false,
            day_ts,
            st,
            1_000,
            true,
        )
        .unwrap();

        let (decision, _trace, _hash) = evaluate_with_config(&tx, cfg);
        assert_eq!(decision, FinalDecision::Approved);
    }

    #[test]
    fn pep_without_kyc_blocks_regardless_of_risk() {
        let st = server_time();
        let tx = TransactionIntent::new(
            "user_pep_low",
            1_000,
            true,
            false,
            st - 60_000,
            st,
            100,
            true,
        )
        .unwrap();

        let (decision, trace, _hash) = evaluate(&tx);
        assert_eq!(decision, FinalDecision::Blocked);

        let has_pep = trace
            .iter()
            .any(|d| matches!(d, Decision::Blocked { rule_id, .. } if *rule_id == "KYC-PEP-002"));
        assert!(has_pep);
    }

    // ========================================================================
    // TESTES ANTI-REPLAY
    // ========================================================================

    #[test]
    fn rejects_zero_amount() {
        let st = server_time();
        let result =
            TransactionIntent::new("user_zero", 0, false, true, st - 60_000, st, 1_000, true);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_empty_user_id() {
        let st = server_time();
        let result = TransactionIntent::new("", 50_000, false, true, st - 60_000, st, 1_000, true);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_future_timestamp() {
        let st = server_time();
        let result = TransactionIntent::new(
            "user_future",
            50_000,
            false,
            true,
            st + 999_999,
            st,
            1_000,
            true,
        );
        assert!(result.is_err());
    }

    #[test]
    fn rejects_replay_timestamp() {
        let st = server_time();
        let result = TransactionIntent::new(
            "user_replay",
            50_000,
            false,
            true,
            st - 999_999,
            st,
            1_000,
            true,
        );
        assert!(result.is_err());
    }

    #[test]
    fn rejects_invalid_risk_bps() {
        let st = server_time();
        let result = TransactionIntent::new(
            "user_risk",
            50_000,
            false,
            true,
            st - 60_000,
            st,
            10_000,
            true,
        );
        assert!(result.is_err());
    }

    #[test]
    fn accepts_max_valid_risk_bps_9999() {
        let st = server_time();
        let result = TransactionIntent::new(
            "user_risk_ok",
            50_000,
            false,
            true,
            st - 60_000,
            st,
            9_999,
            true,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn accepts_timestamp_at_max_drift() {
        let st = server_time();
        let max_drift = 5 * 60 * 1000;
        let result = TransactionIntent::new(
            "user_drift",
            50_000,
            false,
            true,
            st - max_drift,
            st,
            1_000,
            true,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn accepts_future_timestamp_at_max_drift() {
        let st = server_time();
        let max_drift = 5 * 60 * 1000;
        let result = TransactionIntent::new(
            "user_drift_future",
            50_000,
            false,
            true,
            st + max_drift,
            st,
            1_000,
            true,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn night_window_boundary_hours_are_correct() {
        let cfg = cfg_brasil();

        let cases = [
            (19, 59, FinalDecision::Approved),
            (20, 0, FinalDecision::Blocked),
            (6, 59, FinalDecision::Blocked),
            (7, 0, FinalDecision::Approved),
        ];

        for (hour, minute, expected) in cases {
            let (ts, st) = ts_for_local_time(cfg, hour, minute);
            let tx =
                TransactionIntent::new("user_boundary", 100_001, false, true, ts, st, 1_000, true)
                    .unwrap();

            let (decision, _trace, _hash) = evaluate_with_config(&tx, cfg);
            assert_eq!(decision, expected);
        }
    }

    #[test]
    fn timezone_offset_changes_night_rule_outcome() {
        let st_base = server_time();
        let one_day_ms = 86_400_000u64;
        let start_of_day = st_base - (st_base % one_day_ms);
        let noon_utc = start_of_day + 43_200_000;
        let server = noon_utc + 60_000;

        let tx = TransactionIntent::new(
            "user_tz", 200_000, false, true, noon_utc, server, 1_000, true,
        )
        .unwrap();

        let (decision_br, _trace_br, _hash_br) = evaluate_with_config(
            &tx,
            EngineConfig {
                tz_offset_minutes: -180,
                night_start: 20,
                night_end: 6,
                night_limit_cents: 100_000,
                aml_amount_cents: 5_000_000,
                aml_risk_bps: 9_000,
            },
        );
        let (decision_jp, _trace_jp, _hash_jp) = evaluate_with_config(
            &tx,
            EngineConfig {
                tz_offset_minutes: 540,
                night_start: 20,
                night_end: 6,
                night_limit_cents: 100_000,
                aml_amount_cents: 5_000_000,
                aml_risk_bps: 9_000,
            },
        );

        assert_eq!(decision_br, FinalDecision::Approved);
        assert_eq!(decision_jp, FinalDecision::Blocked);
    }

    // ========================================================================
    // TESTES DO HASH BLAKE3
    // ========================================================================

    #[test]
    fn hash_is_deterministic() {
        let tx = base_tx();
        let (_d1, _t1, hash1) = evaluate(&tx);
        let (_d2, _t2, hash2) = evaluate(&tx);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn hash_is_not_empty() {
        let tx = base_tx();
        let (_d, _t, hash) = evaluate(&tx);
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn hash_differs_approved_vs_blocked() {
        let st = server_time();
        let tx_ok = base_tx();
        let (_d, _t, hash_ok) = evaluate(&tx_ok);

        let tx_blocked = TransactionIntent::new(
            "user_pep",
            50_000,
            true,
            false,
            st - 60_000,
            st,
            1_000,
            true,
        )
        .unwrap();

        let (_d, _t, hash_blocked) = evaluate(&tx_blocked);
        assert_ne!(hash_ok, hash_blocked);
    }

    #[test]
    fn hash_changes_when_amount_changes() {
        let st = server_time();

        let tx1 =
            TransactionIntent::new("user_a", 50_000, false, true, st - 60_000, st, 1_000, true)
                .unwrap();

        let tx2 = TransactionIntent::new(
            "user_a",
            5_000_000,
            false,
            true,
            st - 60_000,
            st,
            1_000,
            true,
        )
        .unwrap();

        let (_d1, _t1, hash1) = evaluate(&tx1);
        let (_d2, _t2, hash2) = evaluate(&tx2);
        assert_ne!(hash1, hash2);
    }

    // ========================================================================
    // TESTES DE COMBINAÇÕES
    // ========================================================================

    #[test]
    fn ui_fraud_overrides_everything() {
        let st = server_time();
        let tx = TransactionIntent::new(
            "user_fraud",
            50_000,
            true,
            false,
            st - 60_000,
            st,
            9_000,
            false,
        )
        .unwrap();

        let (decision, trace, _hash) = evaluate(&tx);
        assert_eq!(decision, FinalDecision::Blocked);

        let has_ui_block = trace
            .iter()
            .any(|d| matches!(d, Decision::Blocked { rule_id, .. } if *rule_id == "UI-FRAUD-001"));
        assert!(has_ui_block);
    }

    #[test]
    fn ui_fraud_keeps_full_trace_execution() {
        let st = server_time();
        let tx = TransactionIntent::new(
            "user_fraud_full_trace",
            5_000_000,
            true,
            false,
            st - 60_000,
            st,
            9_000,
            false,
        )
        .unwrap();

        let (decision, trace, _hash) = evaluate(&tx);
        assert_eq!(decision, FinalDecision::Blocked);
        assert_eq!(trace.len(), 3);

        let has_ui_block = trace
            .iter()
            .any(|d| matches!(d, Decision::Blocked { rule_id, .. } if *rule_id == "UI-FRAUD-001"));
        let has_pep_block = trace
            .iter()
            .any(|d| matches!(d, Decision::Blocked { rule_id, .. } if *rule_id == "KYC-PEP-002"));
        assert!(has_ui_block);
        assert!(has_pep_block);
    }

    #[test]
    fn multiple_violations_returns_blocked() {
        let st = server_time();
        let tx = TransactionIntent::new(
            "user_multi",
            5_000_000,
            true,
            false,
            st - 60_000,
            st,
            9_000,
            true,
        )
        .unwrap();

        let (decision, _trace, _hash) = evaluate(&tx);
        assert_eq!(decision, FinalDecision::Blocked);
    }

    // ========================================================================
    // TESTES DE SEVERIDADE
    // ========================================================================

    #[test]
    fn severity_rank_order_is_correct() {
        assert!(Severity::Critica.rank() > Severity::Grave.rank());
        assert!(Severity::Grave.rank() > Severity::Alta.rank());
        assert!(Severity::Alta.rank() > Severity::Baixa.rank());
    }

    #[test]
    fn ui_fraud_has_critica_severity() {
        let st = server_time();
        let tx = TransactionIntent::new(
            "user_fraud",
            50_000,
            false,
            true,
            st - 60_000,
            st,
            1_000,
            false,
        )
        .unwrap();

        let (_decision, trace, _hash) = evaluate(&tx);

        let has_critica = trace.iter().any(|d| {
            matches!(
                d,
                Decision::Blocked {
                    severity: Severity::Critica,
                    ..
                }
            )
        });
        assert!(has_critica);
    }

    #[test]
    fn aml_double_block_has_critica_severity() {
        let st = server_time();
        let tx = TransactionIntent::new(
            "user_aml",
            5_000_000,
            false,
            true,
            st - 60_000,
            st,
            9_000,
            true,
        )
        .unwrap();

        let (_decision, trace, _hash) = evaluate(&tx);

        let has_critica = trace.iter().any(|d| {
            matches!(
                d,
                Decision::Blocked {
                    severity: Severity::Critica,
                    ..
                }
            )
        });
        assert!(has_critica);
    }

    #[test]
    fn hash_depends_on_trace_not_transaction_identity() {
        let st = server_time();
        let tx1 =
            TransactionIntent::new("user_a", 50_000, false, true, st - 60_000, st, 1_000, true)
                .unwrap();
        let tx2 = TransactionIntent::new("user_b", 60_000, false, true, st - 60_000, st, 500, true)
            .unwrap();

        let (_d1, trace1, hash1) = evaluate(&tx1);
        let (_d2, trace2, hash2) = evaluate(&tx2);

        assert_eq!(trace1, trace2);
        assert_eq!(hash1, hash2);
    }
}
