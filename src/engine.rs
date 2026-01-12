use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use serde_sarif::sarif::Artifact;
use serde_sarif::sarif::{MultiformatMessageString, ReportingDescriptor, Result as SarifResult};

use crate::callgraph::{build_call_graph, CallGraph};
use crate::classpath::ClasspathIndex;
use crate::ir::Class;
use crate::rules::{
    dead_code::DeadCodeRule, empty_catch::EmptyCatchRule,
    ineffective_equals::IneffectiveEqualsRule, insecure_api::InsecureApiRule,
    nullness::NullnessRule, Rule, RuleMetadata,
};

/// Inputs shared by analysis rules.
pub(crate) struct AnalysisContext {
    pub(crate) classes: Vec<Class>,
    #[allow(dead_code)]
    pub(crate) classpath: ClasspathIndex,
    pub(crate) call_graph: CallGraph,
    analysis_target_artifacts: BTreeSet<i64>,
    artifact_parents: BTreeMap<i64, i64>,
}

/// Analysis engine that executes configured rules.
pub(crate) struct Engine {
    rules: Vec<Box<dyn Rule>>,
}

impl Engine {
    pub(crate) fn new() -> Self {
        let mut rules: Vec<Box<dyn Rule>> = vec![
            Box::new(DeadCodeRule),
            Box::new(NullnessRule),
            Box::new(EmptyCatchRule),
            Box::new(InsecureApiRule),
            Box::new(IneffectiveEqualsRule),
        ];
        rules.sort_by(|a, b| a.metadata().id.cmp(b.metadata().id));
        Self { rules }
    }

    pub(crate) fn analyze(&self, context: AnalysisContext) -> Result<EngineOutput> {
        let mut rules = Vec::new();
        let mut results = Vec::new();

        for rule in &self.rules {
            let metadata = rule.metadata();
            rules.push(rule_descriptor(&metadata));
            let mut rule_results = rule.run(&context)?;
            for result in &mut rule_results {
                if result.rule_id.is_none() {
                    result.rule_id = Some(metadata.id.to_string());
                }
            }
            results.extend(rule_results);
        }

        results.sort_by(|left, right| {
            let left_id = left.rule_id.as_deref().unwrap_or("");
            let right_id = right.rule_id.as_deref().unwrap_or("");
            let left_msg = left.message.text.as_deref().unwrap_or("").to_string();
            let right_msg = right.message.text.as_deref().unwrap_or("").to_string();
            left_id.cmp(right_id).then(left_msg.cmp(&right_msg))
        });

        Ok(EngineOutput { rules, results })
    }
}

/// Aggregated SARIF payload from rule execution.
pub(crate) struct EngineOutput {
    pub(crate) rules: Vec<ReportingDescriptor>,
    pub(crate) results: Vec<SarifResult>,
}

pub(crate) fn build_context(
    classes: Vec<Class>,
    classpath: ClasspathIndex,
    artifacts: &[Artifact],
) -> AnalysisContext {
    let call_graph = build_call_graph(&classes);
    let (analysis_target_artifacts, artifact_parents) = analyze_artifacts(artifacts);
    AnalysisContext {
        classes,
        classpath,
        call_graph,
        analysis_target_artifacts,
        artifact_parents,
    }
}

fn rule_descriptor(metadata: &RuleMetadata) -> ReportingDescriptor {
    ReportingDescriptor::builder()
        .id(metadata.id)
        .name(metadata.name)
        .short_description(
            MultiformatMessageString::builder()
                .text(metadata.description)
                .build(),
        )
        .build()
}

impl AnalysisContext {
    pub(crate) fn is_analysis_target_class(&self, class: &Class) -> bool {
        if self.analysis_target_artifacts.is_empty() {
            return true;
        }
        let mut current = Some(class.artifact_index);
        while let Some(index) = current {
            if self.analysis_target_artifacts.contains(&index) {
                return true;
            }
            current = self.artifact_parents.get(&index).copied();
        }
        false
    }
}

fn analyze_artifacts(artifacts: &[Artifact]) -> (BTreeSet<i64>, BTreeMap<i64, i64>) {
    let mut analysis_targets = BTreeSet::new();
    let mut parents = BTreeMap::new();
    for (index, artifact) in artifacts.iter().enumerate() {
        let index = index as i64;
        if let Some(parent) = artifact.parent_index {
            parents.insert(index, parent);
        }
        if let Some(roles) = &artifact.roles {
            if roles
                .iter()
                .any(|role| role.as_str() == Some("analysisTarget"))
            {
                analysis_targets.insert(index);
            }
        }
    }
    (analysis_targets, parents)
}
