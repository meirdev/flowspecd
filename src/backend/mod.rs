pub mod nftables;

use crate::bgp::flowspec::{BitmaskMatch, Component, FlowSpecNlri, NumericMatch};

/// Action to take on matched traffic
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Drop,
    Accept,
    RateLimit { bytes_per_sec: f32 },
    Mark { dscp: u8 },
}

/// A compiled FlowSpec rule ready for a backend
#[derive(Debug, Clone)]
pub struct Rule {
    pub components: Vec<Component>,
    pub action: Action,
}

impl Rule {
    pub fn new(nlri: &FlowSpecNlri, action: Action) -> Self {
        Self {
            components: nlri.components.clone(),
            action,
        }
    }
}

/// Backend trait for firewall implementations
pub trait Backend {
    type Error: std::error::Error;

    /// Apply a FlowSpec rule
    fn apply(&mut self, rule: &Rule) -> Result<(), Self::Error>;

    /// Remove a FlowSpec rule
    fn remove(&mut self, rule: &Rule) -> Result<(), Self::Error>;

    /// Clear all FlowSpec rules
    #[allow(dead_code)]
    fn clear(&mut self) -> Result<(), Self::Error>;
}

/// Helper to format a numeric match as a comparison expression
pub fn numeric_match_to_string(matches: &[NumericMatch]) -> String {
    let mut parts = Vec::new();

    for m in matches {
        let val = m.value;
        let expr = if m.op.eq && !m.op.lt && !m.op.gt {
            format!("{}", val)
        } else if m.op.lt && m.op.eq {
            format!("<= {}", val)
        } else if m.op.gt && m.op.eq {
            format!(">= {}", val)
        } else if m.op.lt {
            format!("< {}", val)
        } else if m.op.gt {
            format!("> {}", val)
        } else if !m.op.lt && !m.op.gt && !m.op.eq {
            // false (no match) - shouldn't happen in practice
            format!("!= {}", val)
        } else {
            format!("{}", val)
        };

        parts.push(expr);
    }

    parts.join(", ")
}

/// Helper to format TCP flags from bitmask matches
pub fn tcp_flags_to_string(matches: &[BitmaskMatch]) -> String {
    let mut parts = Vec::new();

    for m in matches {
        let flags = m.value as u16;
        let mut flag_names = Vec::new();

        if flags & 0x01 != 0 {
            flag_names.push("fin");
        }
        if flags & 0x02 != 0 {
            flag_names.push("syn");
        }
        if flags & 0x04 != 0 {
            flag_names.push("rst");
        }
        if flags & 0x08 != 0 {
            flag_names.push("psh");
        }
        if flags & 0x10 != 0 {
            flag_names.push("ack");
        }
        if flags & 0x20 != 0 {
            flag_names.push("urg");
        }

        let expr = if m.op.not {
            format!("!{}", flag_names.join(","))
        } else {
            flag_names.join(",")
        };

        parts.push(expr);
    }

    parts.join(" ")
}
