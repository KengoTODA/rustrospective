use anyhow::Result;
use serde_sarif::sarif::Result as SarifResult;

use crate::engine::AnalysisContext;
use crate::rules::{Rule, RuleMetadata, class_location, result_message};

/// Rule that flags record components that use array types.
pub(crate) struct RecordArrayFieldRule;

impl Rule for RecordArrayFieldRule {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "RECORD_ARRAY_FIELD",
            name: "Record array field",
            description: "Records should not use array-typed components",
        }
    }

    fn run(&self, context: &AnalysisContext) -> Result<Vec<SarifResult>> {
        let mut results = Vec::new();
        for class in &context.classes {
            if !context.is_analysis_target_class(class) || !class.is_record {
                continue;
            }
            for field in &class.fields {
                if field.access.is_static {
                    continue;
                }
                if field.descriptor.starts_with('[') {
                    let message = result_message(format!(
                        "Record component uses array type: {}.{} ({})",
                        class.name, field.name, field.descriptor
                    ));
                    let location = class_location(&class.name);
                    results.push(
                        SarifResult::builder()
                            .message(message)
                            .locations(vec![location])
                            .build(),
                    );
                }
            }
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use crate::test_harness::{JvmTestHarness, Language, SourceFile};

    fn analyze_sources(sources: Vec<SourceFile>) -> Vec<String> {
        let harness = JvmTestHarness::new().expect("JAVA_HOME must be set for harness tests");
        let output = harness
            .compile_and_analyze(Language::Java, &sources, &[])
            .expect("run harness analysis");
        output
            .results
            .iter()
            .filter(|result| result.rule_id.as_deref() == Some("RECORD_ARRAY_FIELD"))
            .filter_map(|result| result.message.text.clone())
            .collect()
    }

    #[test]
    fn record_array_field_reports_array_component() {
        let sources = vec![SourceFile {
            path: "com/example/RecordWithArray.java".to_string(),
            contents: r#"
package com.example;
public record RecordWithArray(String[] values) {}
"#
            .to_string(),
        }];
        let messages = analyze_sources(sources);
        assert!(messages.iter().any(|msg| msg.contains("array type")));
    }

    #[test]
    fn record_array_field_ignores_non_array_component() {
        let sources = vec![SourceFile {
            path: "com/example/RecordOk.java".to_string(),
            contents: r#"
package com.example;
public record RecordOk(String value) {}
"#
            .to_string(),
        }];
        let messages = analyze_sources(sources);
        assert!(messages.is_empty());
    }

    #[test]
    fn record_array_field_ignores_non_record_class() {
        let sources = vec![SourceFile {
            path: "com/example/Plain.java".to_string(),
            contents: r#"
package com.example;
public class Plain {
    private final String[] values;
    public Plain(String[] values) {
        this.values = values;
    }
}
"#
            .to_string(),
        }];
        let messages = analyze_sources(sources);
        assert!(messages.is_empty());
    }

    #[test]
    fn record_array_field_ignores_static_array_field() {
        let sources = vec![SourceFile {
            path: "com/example/RecordWithStatic.java".to_string(),
            contents: r#"
package com.example;
public record RecordWithStatic(String value) {
    public static final String[] VALUES = new String[] {"a"};
}
"#
            .to_string(),
        }];
        let messages = analyze_sources(sources);
        assert!(messages.is_empty());
    }
}
