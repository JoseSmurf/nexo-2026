use crate::Decision;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TraceFormatVersion {
    #[default]
    V1,
}

impl TraceFormatVersion {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::V1 => "1",
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TraceStep {
    pub index: u32,
    pub rule_id: &'static str,
    pub decision: Decision,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DecisionTrace {
    pub schema: &'static str,
    pub format_version: &'static str,
    pub steps: Vec<TraceStep>,
}

impl Default for DecisionTrace {
    fn default() -> Self {
        Self {
            schema: "v1",
            format_version: TraceFormatVersion::V1.as_str(),
            steps: Vec::new(),
        }
    }
}

impl DecisionTrace {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            schema: "v1",
            format_version: TraceFormatVersion::V1.as_str(),
            steps: Vec::with_capacity(capacity),
        }
    }

    pub fn push(&mut self, rule_id: &'static str, decision: Decision) {
        let index = self.steps.len() as u32;
        self.steps.push(TraceStep {
            index,
            rule_id,
            decision,
        });
    }

    pub fn iter(&self) -> impl Iterator<Item = &Decision> {
        self.steps.iter().map(|step| &step.decision)
    }

    pub fn len(&self) -> usize {
        self.steps.len()
    }

    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    pub fn decisions(&self) -> impl Iterator<Item = &Decision> {
        self.iter()
    }

    pub fn into_decisions(self) -> Vec<Decision> {
        self.steps.into_iter().map(|step| step.decision).collect()
    }
}
