use std::collections::BTreeSet;

use serde::Deserialize;

pub const MAX_RELAYS: usize = 16;

#[derive(Debug, Deserialize)]
struct RegistryResponse {
    relays: Vec<String>,
}

pub fn normalize_relays(relays: Vec<String>) -> Vec<String> {
    let mut set = BTreeSet::new();
    for relay in relays {
        let relay = relay.trim().trim_end_matches('/').to_string();
        if relay.starts_with("http://") || relay.starts_with("https://") {
            set.insert(relay);
            if set.len() >= MAX_RELAYS {
                break;
            }
        }
    }
    set.into_iter().collect()
}

pub fn merge_relays(existing: &mut BTreeSet<String>, incoming: &[String]) {
    for relay in incoming {
        if existing.len() >= MAX_RELAYS && !existing.contains(relay) {
            continue;
        }
        existing.insert(relay.clone());
    }
    while existing.len() > MAX_RELAYS {
        if let Some(last) = existing.iter().next_back().cloned() {
            existing.remove(&last);
        } else {
            break;
        }
    }
}

pub async fn fetch_relays(registry_url: &str) -> Result<Vec<String>, String> {
    let base = registry_url.trim_end_matches('/');
    let url = if base.ends_with("/relays") {
        base.to_string()
    } else {
        format!("{base}/relays")
    };
    let resp = reqwest::Client::new()
        .get(url)
        .send()
        .await
        .map_err(|e| format!("registry request failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("registry status={}", resp.status()));
    }
    let body: RegistryResponse = resp
        .json()
        .await
        .map_err(|e| format!("registry parse failed: {e}"))?;
    Ok(normalize_relays(body.relays))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_registry_parses() {
        let relays = normalize_relays(vec![
            "http://a:1".to_string(),
            "http://a:1/".to_string(),
            "invalid".to_string(),
            "https://b:2".to_string(),
        ]);
        assert_eq!(
            relays,
            vec!["http://a:1".to_string(), "https://b:2".to_string()]
        );
    }
}
