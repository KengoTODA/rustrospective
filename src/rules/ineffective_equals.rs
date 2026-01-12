use anyhow::Result;
use serde_sarif::sarif::Result as SarifResult;

use crate::engine::AnalysisContext;
use crate::rules::{class_location, result_message, Rule, RuleMetadata};

/// Rule that flags classes overriding equals or hashCode alone.
pub(crate) struct IneffectiveEqualsRule;

impl Rule for IneffectiveEqualsRule {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "INEFFECTIVE_EQUALS_HASHCODE",
            name: "Ineffective equals/hashCode",
            description: "Classes with equals without hashCode or vice versa",
        }
    }

fn run(&self, context: &AnalysisContext) -> Result<Vec<SarifResult>> {
        let mut results = Vec::new();
        for class in &context.classes {
            let mut has_equals = false;
            let mut has_hashcode = false;
            for method in &class.methods {
                if method.name == "equals" && method.descriptor == "(Ljava/lang/Object;)Z" {
                    has_equals = true;
                }
                if method.name == "hashCode" && method.descriptor == "()I" {
                    has_hashcode = true;
                }
            }
            if has_equals ^ has_hashcode {
                let message = if has_equals {
                    result_message(format!(
                        "Class {} overrides equals without hashCode",
                        class.name
                    ))
                } else {
                    result_message(format!(
                        "Class {} overrides hashCode without equals",
                        class.name
                    ))
                };
                let location = class_location(&class.name);
                results.push(
                    SarifResult::builder()
                        .message(message)
                        .locations(vec![location])
                        .build(),
                );
            }
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classpath::resolve_classpath;
    use crate::engine::build_context;
    use crate::ir::{Class, ControlFlowGraph, Method, MethodAccess};

    fn empty_cfg() -> ControlFlowGraph {
        ControlFlowGraph {
            blocks: Vec::new(),
            edges: Vec::new(),
        }
    }

    fn method_with(name: &str, descriptor: &str) -> Method {
        Method {
            name: name.to_string(),
            descriptor: descriptor.to_string(),
            access: MethodAccess {
                is_public: true,
                is_static: false,
                is_abstract: false,
            },
            bytecode: vec![0],
            cfg: empty_cfg(),
            calls: Vec::new(),
            string_literals: Vec::new(),
            exception_handlers: Vec::new(),
        }
    }

    fn class_with_methods(name: &str, methods: Vec<Method>) -> Class {
        Class {
            name: name.to_string(),
            super_name: None,
            referenced_classes: Vec::new(),
            methods,
            artifact_index: 0,
        }
    }

    fn context_for(classes: Vec<Class>) -> crate::engine::AnalysisContext {
        let classpath = resolve_classpath(&classes).expect("classpath build");
        build_context(classes, classpath, &[])
    }

    #[test]
    fn ineffective_equals_rule_reports_missing_pair() {
        let equals = method_with("equals", "(Ljava/lang/Object;)Z");
        let classes = vec![class_with_methods("com/example/Value", vec![equals])];
        let context = context_for(classes);

        let results =
            IneffectiveEqualsRule.run(&context).expect("ineffective equals rule run");

        assert_eq!(1, results.len());
        let message = results[0].message.text.as_deref().unwrap_or("");
        assert!(message.contains("overrides equals without hashCode"));
    }

    #[test]
    fn ineffective_equals_rule_ignores_complete_pairs() {
        let equals = method_with("equals", "(Ljava/lang/Object;)Z");
        let hashcode = method_with("hashCode", "()I");
        let classes = vec![class_with_methods(
            "com/example/Value",
            vec![equals, hashcode],
        )];
        let context = context_for(classes);

        let results =
            IneffectiveEqualsRule.run(&context).expect("ineffective equals rule run");

        assert!(results.is_empty());
    }

    #[test]
    fn ineffective_equals_rule_ignores_mismatched_signatures() {
        let equals = method_with("equals", "()Z");
        let classes = vec![class_with_methods("com/example/Value", vec![equals])];
        let context = context_for(classes);

        let results =
            IneffectiveEqualsRule.run(&context).expect("ineffective equals rule run");

        assert!(results.is_empty());
    }
}
