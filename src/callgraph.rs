use std::collections::{BTreeMap, BTreeSet};

use crate::ir::{CallKind, CallSite, Class};

/// Unique identifier for a method in the classpath.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct MethodId {
    pub(crate) class_name: String,
    pub(crate) name: String,
    pub(crate) descriptor: String,
}

/// Directed call edge between caller and callee.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct CallEdge {
    pub(crate) caller: MethodId,
    pub(crate) callee: MethodId,
    pub(crate) kind: CallKind,
    pub(crate) offset: u32,
}

/// Call graph built from CHA on the parsed classpath.
#[derive(Clone, Debug, Default)]
pub(crate) struct CallGraph {
    pub(crate) edges: BTreeSet<CallEdge>,
}

/// Build a call graph using a CHA baseline.
pub(crate) fn build_call_graph(classes: &[Class]) -> CallGraph {
    let hierarchy = build_hierarchy(classes);
    let methods = index_methods(classes);
    let edges = build_edges(classes, &hierarchy, &methods);
    CallGraph { edges }
}

fn build_edges(
    classes: &[Class],
    hierarchy: &BTreeMap<String, Vec<String>>,
    methods: &BTreeMap<MethodId, ()>,
) -> BTreeSet<CallEdge> {
    let mut edges = BTreeSet::new();
    for class in classes {
        for method in &class.methods {
            let caller = MethodId {
                class_name: class.name.clone(),
                name: method.name.clone(),
                descriptor: method.descriptor.clone(),
            };
            for call in &method.calls {
                let targets = resolve_targets(call, hierarchy, methods);
                for callee in targets {
                    edges.insert(CallEdge {
                        caller: caller.clone(),
                        callee,
                        kind: call.kind,
                        offset: call.offset,
                    });
                }
            }
        }
    }
    edges
}

fn resolve_targets(
    call: &CallSite,
    hierarchy: &BTreeMap<String, Vec<String>>,
    methods: &BTreeMap<MethodId, ()>,
) -> Vec<MethodId> {
    let mut targets = Vec::new();
    let base = MethodId {
        class_name: call.owner.clone(),
        name: call.name.clone(),
        descriptor: call.descriptor.clone(),
    };
    match call.kind {
        CallKind::Static | CallKind::Special => {
            if methods.contains_key(&base) {
                targets.push(base);
            }
        }
        CallKind::Virtual | CallKind::Interface => {
            let mut candidates = vec![call.owner.clone()];
            if let Some(descendants) = hierarchy.get(&call.owner) {
                candidates.extend(descendants.iter().cloned());
            }
            candidates.sort();
            candidates.dedup();
            for class_name in candidates {
                let candidate = MethodId {
                    class_name,
                    name: call.name.clone(),
                    descriptor: call.descriptor.clone(),
                };
                if methods.contains_key(&candidate) {
                    targets.push(candidate);
                }
            }
        }
    }
    targets
}

fn build_hierarchy(classes: &[Class]) -> BTreeMap<String, Vec<String>> {
    let mut hierarchy = BTreeMap::new();
    for class in classes {
        if let Some(super_name) = &class.super_name {
            hierarchy
                .entry(super_name.clone())
                .or_insert_with(Vec::new)
                .push(class.name.clone());
        }
    }
    for descendants in hierarchy.values_mut() {
        descendants.sort();
        descendants.dedup();
    }
    hierarchy
}

fn index_methods(classes: &[Class]) -> BTreeMap<MethodId, ()> {
    let mut map = BTreeMap::new();
    for class in classes {
        for method in &class.methods {
            map.insert(
                MethodId {
                    class_name: class.name.clone(),
                    name: method.name.clone(),
                    descriptor: method.descriptor.clone(),
                },
                (),
            );
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{CallSite, Method, MethodAccess};

    fn class_with_method(name: &str, super_name: Option<&str>, method: &Method) -> Class {
        Class {
            name: name.to_string(),
            super_name: super_name.map(str::to_string),
            referenced_classes: Vec::new(),
            methods: vec![method.clone()],
            artifact_index: 0,
        }
    }

    #[test]
    fn call_graph_includes_virtual_targets() {
        let caller = Method {
            name: "caller".to_string(),
            descriptor: "()V".to_string(),
            access: MethodAccess {
                is_public: true,
                is_static: false,
                is_abstract: false,
            },
            bytecode: Vec::new(),
            cfg: crate::ir::ControlFlowGraph {
                blocks: Vec::new(),
                edges: Vec::new(),
            },
            calls: vec![CallSite {
                owner: "com/example/Base".to_string(),
                name: "target".to_string(),
                descriptor: "()V".to_string(),
                kind: CallKind::Virtual,
                offset: 0,
            }],
            string_literals: Vec::new(),
            exception_handlers: Vec::new(),
        };
        let base_method = Method {
            name: "target".to_string(),
            descriptor: "()V".to_string(),
            access: MethodAccess {
                is_public: true,
                is_static: false,
                is_abstract: false,
            },
            bytecode: Vec::new(),
            cfg: crate::ir::ControlFlowGraph {
                blocks: Vec::new(),
                edges: Vec::new(),
            },
            calls: Vec::new(),
            string_literals: Vec::new(),
            exception_handlers: Vec::new(),
        };
        let subclass_method = base_method.clone();
        let classes = vec![
            class_with_method("com/example/Caller", None, &caller),
            class_with_method("com/example/Base", None, &base_method),
            class_with_method(
                "com/example/Sub",
                Some("com/example/Base"),
                &subclass_method,
            ),
        ];

        let graph = build_call_graph(&classes);

        assert!(!graph.edges.is_empty());
    }
}
