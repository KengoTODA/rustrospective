use std::collections::{BTreeMap, BTreeSet, VecDeque};

use anyhow::Result;
use serde_sarif::sarif::Result as SarifResult;

use crate::callgraph::MethodId;
use crate::engine::AnalysisContext;
use crate::ir::Method;
use crate::rules::{method_location, result_message, Rule, RuleMetadata};

/// Rule that detects unreachable methods.
pub(crate) struct DeadCodeRule;

impl Rule for DeadCodeRule {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "DEAD_CODE",
            name: "Dead code",
            description: "Unreachable methods detected by call graph",
        }
    }

    fn run(&self, context: &AnalysisContext) -> Result<Vec<SarifResult>> {
        let mut method_map = BTreeMap::new();
        let mut entry_points = Vec::new();

        for class in &context.classes {
            if !context.is_analysis_target_class(class) {
                continue;
            }
            for method in &class.methods {
                let id = MethodId {
                    class_name: class.name.clone(),
                    name: method.name.clone(),
                    descriptor: method.descriptor.clone(),
                };
                method_map.insert(id.clone(), (class.name.clone(), method));
                if is_entry_method(method) {
                    entry_points.push(id);
                }
            }
        }

        if entry_points.is_empty() {
            return Ok(Vec::new());
        }

        let adjacency = build_adjacency(&context.call_graph.edges);
        let reachable = walk_graph(&entry_points, &adjacency);

        let mut results = Vec::new();
        for (id, (class_name, method)) in method_map {
            if reachable.contains(&id) {
                continue;
            }
            if !method_has_body(method) {
                continue;
            }
            let message = result_message(format!(
                "Unreachable method: {}.{}{}",
                class_name, method.name, method.descriptor
            ));
            let location = method_location(&class_name, &method.name, &method.descriptor);
            results.push(
                SarifResult::builder()
                    .message(message)
                    .locations(vec![location])
                    .build(),
            );
        }

        Ok(results)
    }
}

fn build_adjacency(
    edges: &BTreeSet<crate::callgraph::CallEdge>,
) -> BTreeMap<MethodId, Vec<MethodId>> {
    let mut adjacency = BTreeMap::new();
    for edge in edges {
        adjacency
            .entry(edge.caller.clone())
            .or_insert_with(Vec::new)
            .push(edge.callee.clone());
    }
    adjacency
}

fn walk_graph(
    entries: &[MethodId],
    adjacency: &BTreeMap<MethodId, Vec<MethodId>>,
) -> BTreeSet<MethodId> {
    let mut visited = BTreeSet::new();
    let mut queue = VecDeque::new();
    for entry in entries {
        if visited.insert(entry.clone()) {
            queue.push_back(entry.clone());
        }
    }
    while let Some(node) = queue.pop_front() {
        if let Some(neighbors) = adjacency.get(&node) {
            for neighbor in neighbors {
                if visited.insert(neighbor.clone()) {
                    queue.push_back(neighbor.clone());
                }
            }
        }
    }
    visited
}

fn is_entry_method(method: &Method) -> bool {
    method.access.is_public
}

fn method_has_body(method: &Method) -> bool {
    !method.access.is_abstract && !method.bytecode.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classpath::resolve_classpath;
    use crate::engine::build_context;
    use crate::ir::{CallKind, CallSite, Class, ControlFlowGraph, MethodAccess};

    fn empty_cfg() -> ControlFlowGraph {
        ControlFlowGraph {
            blocks: Vec::new(),
            edges: Vec::new(),
        }
    }

    fn method_with(
        name: &str,
        descriptor: &str,
        access: MethodAccess,
        bytecode: Vec<u8>,
        calls: Vec<CallSite>,
    ) -> Method {
        Method {
            name: name.to_string(),
            descriptor: descriptor.to_string(),
            access,
            bytecode,
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
    fn dead_code_rule_reports_unreachable_method() {
        let main_method = method_with(
            "main",
            "([Ljava/lang/String;)V",
            MethodAccess {
                is_public: true,
                is_static: true,
                is_abstract: false,
            },
            vec![0],
            vec![CallSite {
                owner: "com/example/App".to_string(),
                name: "reachable".to_string(),
                descriptor: "()V".to_string(),
                kind: CallKind::Static,
                offset: 0,
            }],
        );
        let reachable = method_with(
            "reachable",
            "()V",
            MethodAccess {
                is_public: false,
                is_static: true,
                is_abstract: false,
            },
            vec![0],
            Vec::new(),
        );
        let unreachable = method_with(
            "unreachable",
            "()V",
            MethodAccess {
                is_public: false,
                is_static: false,
                is_abstract: false,
            },
            vec![0],
            Vec::new(),
        );
        let classes = vec![class_with_methods(
            "com/example/App",
            vec![main_method, reachable, unreachable],
        )];
        let context = context_for(classes);

        let results = DeadCodeRule.run(&context).expect("dead code rule run");

        assert_eq!(1, results.len());
        let message = results[0].message.text.as_deref().unwrap_or("");
        assert!(message.contains("Unreachable method: com/example/App.unreachable()V"));
    }

    #[test]
    fn dead_code_rule_skips_when_no_entrypoints() {
        let helper = method_with(
            "helper",
            "()V",
            MethodAccess {
                is_public: true,
                is_static: false,
                is_abstract: false,
            },
            vec![0],
            Vec::new(),
        );
        let classes = vec![class_with_methods("com/example/Util", vec![helper])];
        let context = context_for(classes);

        let results = DeadCodeRule.run(&context).expect("dead code rule run");

        assert!(results.is_empty());
    }

    #[test]
    fn dead_code_rule_skips_methods_without_body() {
        let main_method = method_with(
            "main",
            "([Ljava/lang/String;)V",
            MethodAccess {
                is_public: true,
                is_static: true,
                is_abstract: false,
            },
            vec![0],
            Vec::new(),
        );
        let unreachable = method_with(
            "unreachable",
            "()V",
            MethodAccess {
                is_public: true,
                is_static: false,
                is_abstract: false,
            },
            Vec::new(),
            Vec::new(),
        );
        let classes = vec![class_with_methods(
            "com/example/App",
            vec![main_method, unreachable],
        )];
        let context = context_for(classes);

        let results = DeadCodeRule.run(&context).expect("dead code rule run");

        assert!(results.is_empty());
    }
}
