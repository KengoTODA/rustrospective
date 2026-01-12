use anyhow::Result;
use serde_sarif::sarif::Result as SarifResult;

use crate::engine::AnalysisContext;
use crate::rules::{method_location, result_message, Rule, RuleMetadata};

/// Rule that detects insecure API usage.
pub(crate) struct InsecureApiRule;

impl Rule for InsecureApiRule {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "INSECURE_API",
            name: "Insecure API usage",
            description: "Calls to insecure process or reflection APIs",
        }
    }

    fn run(&self, context: &AnalysisContext) -> Result<Vec<SarifResult>> {
        let mut results = Vec::new();
        for class in &context.classes {
            for method in &class.methods {
                for call in &method.calls {
                    if is_insecure_call(&call.owner, &call.name) {
                        let message = result_message(format!(
                            "Insecure API usage: {}.{}",
                            call.owner, call.name
                        ));
                        let location =
                            method_location(&class.name, &method.name, &method.descriptor);
                        results.push(
                            SarifResult::builder()
                                .message(message)
                                .locations(vec![location])
                                .build(),
                        );
                    }
                }
            }
        }
        Ok(results)
    }
}

fn is_insecure_call(owner: &str, name: &str) -> bool {
    matches!(
        (owner, name),
        ("java/lang/Runtime", "exec")
            | ("java/lang/ProcessBuilder", "<init>")
            | ("java/lang/ProcessBuilder", "start")
            | ("java/lang/reflect/Method", "invoke")
            | ("java/lang/reflect/Constructor", "newInstance")
            | ("java/lang/Class", "forName")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classpath::resolve_classpath;
    use crate::engine::build_context;
    use crate::ir::{
        CallKind, CallSite, Class, ControlFlowGraph, Method, MethodAccess,
    };

    fn empty_cfg() -> ControlFlowGraph {
        ControlFlowGraph {
            blocks: Vec::new(),
            edges: Vec::new(),
        }
    }

    fn method_with(name: &str, calls: Vec<CallSite>) -> Method {
        Method {
            name: name.to_string(),
            descriptor: "()V".to_string(),
            access: MethodAccess {
                is_public: true,
                is_static: false,
                is_abstract: false,
            },
            bytecode: vec![0],
            cfg: empty_cfg(),
            calls,
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
    fn insecure_api_rule_reports_matches() {
        let method = method_with(
            "run",
            vec![CallSite {
                owner: "java/lang/Runtime".to_string(),
                name: "exec".to_string(),
                descriptor: "(Ljava/lang/String;)V".to_string(),
                kind: CallKind::Virtual,
                offset: 0,
            }],
        );
        let classes = vec![class_with_methods("com/example/App", vec![method])];
        let context = context_for(classes);

        let results = InsecureApiRule.run(&context).expect("insecure api rule run");

        assert_eq!(1, results.len());
        let message = results[0].message.text.as_deref().unwrap_or("");
        assert!(message.contains("Insecure API usage: java/lang/Runtime.exec"));
    }

    #[test]
    fn insecure_api_rule_ignores_safe_calls() {
        let method = method_with(
            "run",
            vec![CallSite {
                owner: "java/lang/String".to_string(),
                name: "length".to_string(),
                descriptor: "()I".to_string(),
                kind: CallKind::Virtual,
                offset: 0,
            }],
        );
        let classes = vec![class_with_methods("com/example/App", vec![method])];
        let context = context_for(classes);

        let results = InsecureApiRule.run(&context).expect("insecure api rule run");

        assert!(results.is_empty());
    }
}
