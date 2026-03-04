use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Analysis {
    pub intent: &'static str,
    pub topics: Vec<String>,
    pub summary: String,
    pub token_counts: Vec<(String, usize)>,
}

const INTENT_RULES: [(&str, &[&str]); 4] = [
    (
        "transaction",
        &[
            "transfer", "send", "pay", "payment", "pix", "deposit", "withdraw",
        ],
    ),
    (
        "security",
        &[
            "fraud",
            "blocked",
            "attack",
            "replay",
            "invalid",
            "signature",
            "auth",
            "security",
        ],
    ),
    (
        "support",
        &[
            "help", "error", "issue", "problem", "support", "fail", "failed",
        ],
    ),
    (
        "greeting",
        &["hello", "hi", "oi", "bomdia", "boa", "tarde", "noite"],
    ),
];

pub fn tokenize(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for ch in input.chars() {
        let c = ch.to_ascii_lowercase();
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            current.push(c);
        } else if !current.is_empty() {
            out.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

pub fn count_tokens_sorted(tokens: &[String]) -> Vec<(String, usize)> {
    let mut counts = BTreeMap::<String, usize>::new();
    for t in tokens {
        let entry = counts.entry(t.clone()).or_insert(0);
        *entry += 1;
    }

    let mut pairs: Vec<(String, usize)> = counts.into_iter().collect();
    // Stable and deterministic ordering: frequency DESC, token ASC.
    pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    pairs
}

pub fn classify_intent(token_counts: &[(String, usize)]) -> &'static str {
    let mut best_intent = "unknown";
    let mut best_score = 0usize;

    for (intent, words) in INTENT_RULES {
        let mut score = 0usize;
        for (token, n) in token_counts {
            if words.iter().any(|w| *w == token) {
                score = score.saturating_add(*n);
            }
        }
        if score > best_score {
            best_score = score;
            best_intent = intent;
        }
    }
    best_intent
}

fn extract_topics(token_counts: &[(String, usize)], max_topics: usize) -> Vec<String> {
    token_counts
        .iter()
        .filter(|(t, _)| !t.is_empty())
        .take(max_topics)
        .map(|(t, _)| t.clone())
        .collect()
}

pub fn analyze_text(input: &str) -> Analysis {
    let tokens = tokenize(input);
    let token_counts = count_tokens_sorted(&tokens);
    let intent = classify_intent(&token_counts);
    let topics = extract_topics(&token_counts, 3);
    let summary = format!(
        "intent={} token_count={} unique_tokens={} top_topic={}",
        intent,
        tokens.len(),
        token_counts.len(),
        topics.first().map_or("none", String::as_str)
    );
    Analysis {
        intent,
        topics,
        summary,
        token_counts,
    }
}

pub fn analyze_bytes(input: &[u8]) -> Analysis {
    let text = String::from_utf8_lossy(input);
    analyze_text(&text)
}

pub fn deterministic_ai_response(prompt: &[u8]) -> String {
    let analysis = analyze_bytes(prompt);
    let topics = if analysis.topics.is_empty() {
        "none".to_string()
    } else {
        analysis.topics.join(",")
    };
    match analysis.intent {
        "transaction" => format!(
            "deterministic_ai intent=transaction action=review_payment topics={topics} policy=strict"
        ),
        "security" => format!(
            "deterministic_ai intent=security action=escalate_validation topics={topics} policy=fail_closed"
        ),
        "support" => format!(
            "deterministic_ai intent=support action=provide_steps topics={topics} policy=deterministic"
        ),
        "greeting" => format!(
            "deterministic_ai intent=greeting action=acknowledge topics={topics} policy=deterministic"
        ),
        _ => format!(
            "deterministic_ai intent=unknown action=request_clarification topics={topics} policy=deterministic"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenize_is_deterministic_and_ascii_filtered() {
        let in_text = "HeLLo, PIX!!! 123 _ ÁÇ";
        let a = tokenize(in_text);
        let b = tokenize(in_text);
        assert_eq!(a, b);
        assert_eq!(a, vec!["hello", "pix", "123"]);
    }

    #[test]
    fn token_count_sort_is_stable_and_deterministic() {
        let tokens = vec![
            "beta".to_string(),
            "alpha".to_string(),
            "beta".to_string(),
            "alpha".to_string(),
            "zeta".to_string(),
        ];
        let counts = count_tokens_sorted(&tokens);
        assert_eq!(
            counts,
            vec![
                ("alpha".to_string(), 2),
                ("beta".to_string(), 2),
                ("zeta".to_string(), 1)
            ]
        );
    }

    #[test]
    fn classify_intent_uses_fixed_dictionary() {
        let a = analyze_text("please help error invalid signature");
        assert_eq!(a.intent, "security");
    }

    #[test]
    fn full_analysis_is_deterministic() {
        let input = "send payment now";
        let a = analyze_text(input);
        let b = analyze_text(input);
        assert_eq!(a, b);
        assert_eq!(a.intent, "transaction");
    }

    #[test]
    fn deterministic_ai_response_is_stable() {
        let prompt = b"help invalid signature";
        let a = deterministic_ai_response(prompt);
        let b = deterministic_ai_response(prompt);
        assert_eq!(a, b);
        assert!(a.contains("intent=security"));
    }
}
