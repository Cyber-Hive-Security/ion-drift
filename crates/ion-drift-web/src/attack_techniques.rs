//! ATT&CK technique lookup database — loaded from static JSON at compile time.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// A single MITRE ATT&CK technique.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackTechnique {
    pub id: String,
    pub name: String,
    pub tactic: String,
    pub description: String,
    pub url: String,
}

/// Static ATT&CK technique database loaded at startup.
#[derive(Debug, Clone, Serialize)]
pub struct AttackTechniqueDb {
    pub techniques: HashMap<String, AttackTechnique>,
    pub deviation_mappings: HashMap<String, Vec<String>>,
}

#[derive(Deserialize)]
struct RawDb {
    techniques: HashMap<String, AttackTechnique>,
    deviation_mappings: HashMap<String, Vec<String>>,
}

static ATTACK_JSON: &str = include_str!("../../../data/attack_techniques.json");

impl AttackTechniqueDb {
    /// Load the ATT&CK technique database from the embedded JSON.
    pub fn load() -> Self {
        let raw: RawDb = serde_json::from_str(ATTACK_JSON)
            .expect("attack_techniques.json is invalid — this is a build error");
        Self {
            techniques: raw.techniques,
            deviation_mappings: raw.deviation_mappings,
        }
    }

    /// Get technique IDs mapped to a deviation type (e.g., "dns" → [T1071.004, ...]).
    pub fn techniques_for_deviation(&self, deviation_type: &str) -> Vec<String> {
        // Strip subtypes: "dns_unauthorized" → "dns"
        let base_type = deviation_type.split('_').next().unwrap_or(deviation_type);
        self.deviation_mappings
            .get(base_type)
            .cloned()
            .unwrap_or_default()
    }

    /// Get a technique by ID.
    pub fn get(&self, id: &str) -> Option<&AttackTechnique> {
        self.techniques.get(id)
    }
}
