use anyhow::Result;
use serde_sarif::sarif::Result as SarifResult;

use crate::engine::AnalysisContext;
use crate::rules::{Rule, RuleMetadata};

/// Rule that will enforce JSpecify-guided nullness checks.
pub(crate) struct NullnessRule;

impl Rule for NullnessRule {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "NULLNESS",
            name: "Nullness checks",
            description: "Nullness issues guided by JSpecify annotations",
        }
    }

    fn run(&self, _context: &AnalysisContext) -> Result<Vec<SarifResult>> {
        // TODO: Implement JSpecify-guided nullness checks once annotations are indexed.
        Ok(Vec::new())
    }
}
