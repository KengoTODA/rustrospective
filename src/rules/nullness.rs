use std::collections::{BTreeMap, BTreeSet, VecDeque};

use anyhow::Result;
use serde_sarif::sarif::Result as SarifResult;

use crate::descriptor::{ReturnKind, method_param_count, method_return_kind};
use crate::engine::AnalysisContext;
use crate::ir::{CallKind, Class, Method, Nullness};
use crate::opcodes;
use crate::rules::{Rule, RuleMetadata, method_location_with_line, result_message};

// TODO: refer Checkerframework stubs or somthing like it to handle nellness of standard APIs

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

    fn run(&self, context: &AnalysisContext) -> Result<Vec<SarifResult>> {
        let mut results = Vec::new();
        let mut class_map = BTreeMap::new();
        for class in &context.classes {
            class_map.insert(class.name.clone(), class);
        }

        for class in &context.classes {
            if !context.is_analysis_target_class(class) {
                continue;
            }
            results.extend(check_overrides(class, &class_map));
            for method in &class.methods {
                if method.bytecode.is_empty() {
                    continue;
                }
                let artifact_uri = context.class_artifact_uri(class);
                results.extend(check_method_flow(
                    class,
                    method,
                    &class_map,
                    artifact_uri.as_deref(),
                )?);
            }
        }

        Ok(results)
    }
}

fn check_overrides(class: &Class, class_map: &BTreeMap<String, &Class>) -> Vec<SarifResult> {
    let mut results = Vec::new();
    let supertypes = collect_supertypes(class, class_map);
    for method in &class.methods {
        for super_class in &supertypes {
            let Some(base_method) = find_method(super_class, &method.name, &method.descriptor)
            else {
                continue;
            };
            if base_method.nullness.return_nullness == Nullness::NonNull
                && method.nullness.return_nullness == Nullness::Nullable
            {
                let message = result_message(format!(
                    "Nullness override: {}.{}{} returns @Nullable but overrides @NonNull",
                    class.name, method.name, method.descriptor
                ));
                let location = method_location_with_line(
                    &class.name,
                    &method.name,
                    &method.descriptor,
                    None,
                    None,
                );
                results.push(
                    SarifResult::builder()
                        .message(message)
                        .locations(vec![location])
                        .build(),
                );
            }
            let param_count = method.nullness.parameter_nullness.len();
            let base_param_count = base_method.nullness.parameter_nullness.len();
            let count = param_count.min(base_param_count);
            for index in 0..count {
                if base_method.nullness.parameter_nullness[index] == Nullness::Nullable
                    && method.nullness.parameter_nullness[index] == Nullness::NonNull
                {
                    let message = result_message(format!(
                        "Nullness override: {}.{}{} parameter {} is @NonNull but overrides @Nullable",
                        class.name, method.name, method.descriptor, index
                    ));
                    let location = method_location_with_line(
                        &class.name,
                        &method.name,
                        &method.descriptor,
                        None,
                        None,
                    );
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
    results
}

fn collect_supertypes<'a>(
    class: &'a Class,
    class_map: &'a BTreeMap<String, &'a Class>,
) -> Vec<&'a Class> {
    let mut result = Vec::new();
    let mut seen = BTreeSet::new();
    let mut queue = VecDeque::new();
    if let Some(super_name) = &class.super_name {
        queue.push_back(super_name.clone());
    }
    for interface in &class.interfaces {
        queue.push_back(interface.clone());
    }
    while let Some(name) = queue.pop_front() {
        if !seen.insert(name.clone()) {
            continue;
        }
        let Some(super_class) = class_map.get(&name) else {
            continue;
        };
        result.push(*super_class);
        if let Some(super_name) = &super_class.super_name {
            queue.push_back(super_name.clone());
        }
        for interface in &super_class.interfaces {
            queue.push_back(interface.clone());
        }
    }
    result
}

fn find_method<'a>(class: &'a Class, name: &str, descriptor: &str) -> Option<&'a Method> {
    class
        .methods
        .iter()
        .find(|method| method.name == name && method.descriptor == descriptor)
}

fn check_method_flow(
    class: &Class,
    method: &Method,
    class_map: &BTreeMap<String, &Class>,
    artifact_uri: Option<&str>,
) -> Result<Vec<SarifResult>> {
    let mut results = Vec::new();
    let mut callsite_by_offset = BTreeMap::new();
    for call in &method.calls {
        callsite_by_offset.insert(call.offset, call);
    }

    let local_count = local_count(method)?;
    let mut initial_locals = vec![Nullness::Unknown; local_count];
    if !method.access.is_static && !initial_locals.is_empty() {
        initial_locals[0] = Nullness::NonNull;
    }
    let base_index = if method.access.is_static { 0 } else { 1 };
    for (index, nullness) in method.nullness.parameter_nullness.iter().enumerate() {
        let local_index = base_index + index;
        if let Some(local) = initial_locals.get_mut(local_index) {
            *local = *nullness;
        }
    }
    let entry_state = State {
        locals: initial_locals,
        stack: Vec::new(),
    };

    let mut block_map = BTreeMap::new();
    for block in &method.cfg.blocks {
        block_map.insert(block.start_offset, block);
    }
    let mut predecessors: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    let mut successors: BTreeMap<u32, Vec<(u32, crate::ir::EdgeKind)>> = BTreeMap::new();
    for edge in &method.cfg.edges {
        predecessors.entry(edge.to).or_default().push(edge.from);
        successors
            .entry(edge.from)
            .or_default()
            .push((edge.to, edge.kind));
    }

    let mut in_states: BTreeMap<u32, State> = BTreeMap::new();
    let mut out_states: BTreeMap<u32, State> = BTreeMap::new();
    let mut worklist = VecDeque::new();
    if block_map.contains_key(&0) {
        in_states.insert(0, entry_state.clone());
        worklist.push_back(0);
    }

    while let Some(block_start) = worklist.pop_front() {
        let Some(block) = block_map.get(&block_start) else {
            continue;
        };
        let in_state = match predecessors.get(&block_start) {
            Some(preds) if block_start != 0 => {
                let mut merged: Option<State> = None;
                for pred in preds {
                    if let Some(state) = out_states.get(pred) {
                        merged = Some(match merged {
                            Some(existing) => join_states(&existing, state),
                            None => state.clone(),
                        });
                    }
                }
                merged.unwrap_or_else(|| in_states[&block_start].clone())
            }
            _ => in_states
                .get(&block_start)
                .cloned()
                .unwrap_or_else(|| entry_state.clone()),
        };

        let transfer = transfer_block(
            class,
            method,
            block,
            &in_state,
            &callsite_by_offset,
            class_map,
            artifact_uri,
        )?;
        let out_state = transfer.out_state.clone();
        out_states.insert(block_start, out_state.clone());

        if let Some(succs) = successors.get(&block_start) {
            for (succ, kind) in succs {
                let mut next_state = out_state.clone();
                if let Some(refinement) = transfer.branch_refinement.as_ref() {
                    if matches!(kind, crate::ir::EdgeKind::Branch) {
                        next_state = refinement.apply_to(&next_state, BranchKind::Branch);
                    } else if matches!(kind, crate::ir::EdgeKind::FallThrough) {
                        next_state = refinement.apply_to(&next_state, BranchKind::FallThrough);
                    }
                }
                let updated = match in_states.get(succ) {
                    Some(existing) => join_states(existing, &next_state),
                    None => next_state,
                };
                let should_push = match in_states.get(succ) {
                    Some(existing) => &updated != existing,
                    None => true,
                };
                in_states.insert(*succ, updated);
                if should_push {
                    worklist.push_back(*succ);
                }
            }
        }

        results.extend(transfer.results);
    }

    Ok(results)
}

/// Nullness state at a program point.
#[derive(Clone, Debug, PartialEq)]
struct State {
    locals: Vec<Nullness>,
    stack: Vec<StackValue>,
}

/// Operand stack entry with optional local aliasing metadata.
#[derive(Clone, Debug, PartialEq)]
struct StackValue {
    nullness: Nullness,
    local: Option<usize>,
}

/// Transfer output for a basic block, including emitted results.
#[derive(Clone)]
struct BlockTransfer {
    out_state: State,
    branch_refinement: Option<BranchRefinement>,
    results: Vec<SarifResult>,
}

/// Nullness refinement applied on conditional branch edges.
#[derive(Clone)]
struct BranchRefinement {
    local: usize,
    branch_nullness: Nullness,
    fallthrough_nullness: Nullness,
}

enum BranchKind {
    Branch,
    FallThrough,
}

impl BranchRefinement {
    fn apply_to(&self, state: &State, kind: BranchKind) -> State {
        let mut next = state.clone();
        let value = match kind {
            BranchKind::Branch => self.branch_nullness,
            BranchKind::FallThrough => self.fallthrough_nullness,
        };
        if let Some(local) = next.locals.get_mut(self.local) {
            *local = value;
        }
        next
    }
}

fn transfer_block(
    class: &Class,
    method: &Method,
    block: &crate::ir::BasicBlock,
    input: &State,
    callsite_by_offset: &BTreeMap<u32, &crate::ir::CallSite>,
    class_map: &BTreeMap<String, &Class>,
    artifact_uri: Option<&str>,
) -> Result<BlockTransfer> {
    let mut state = input.clone();
    let mut results = Vec::new();
    let mut branch_refinement = None;
    for (index, inst) in block.instructions.iter().enumerate() {
        let is_last = index + 1 == block.instructions.len();
        match inst.opcode {
            opcodes::ACONST_NULL => {
                state.stack.push(StackValue {
                    nullness: Nullness::Nullable,
                    local: None,
                });
            }
            opcodes::ALOAD => {
                let local_index = method
                    .bytecode
                    .get(inst.offset as usize + 1)
                    .copied()
                    .unwrap_or(0) as usize;
                let nullness = state
                    .locals
                    .get(local_index)
                    .copied()
                    .unwrap_or(Nullness::Unknown);
                state.stack.push(StackValue {
                    nullness,
                    local: Some(local_index),
                });
            }
            opcodes::ALOAD_0 | opcodes::ALOAD_1 | opcodes::ALOAD_2 | opcodes::ALOAD_3 => {
                let local_index = (inst.opcode - opcodes::ALOAD_0) as usize;
                let nullness = state
                    .locals
                    .get(local_index)
                    .copied()
                    .unwrap_or(Nullness::Unknown);
                state.stack.push(StackValue {
                    nullness,
                    local: Some(local_index),
                });
            }
            opcodes::ASTORE => {
                let local_index = method
                    .bytecode
                    .get(inst.offset as usize + 1)
                    .copied()
                    .unwrap_or(0) as usize;
                let value = state.stack.pop().unwrap_or(StackValue {
                    nullness: Nullness::Unknown,
                    local: None,
                });
                if let Some(local) = state.locals.get_mut(local_index) {
                    *local = value.nullness;
                }
            }
            opcodes::ASTORE_0 | opcodes::ASTORE_1 | opcodes::ASTORE_2 | opcodes::ASTORE_3 => {
                let local_index = (inst.opcode - opcodes::ASTORE_0) as usize;
                let value = state.stack.pop().unwrap_or(StackValue {
                    nullness: Nullness::Unknown,
                    local: None,
                });
                if let Some(local) = state.locals.get_mut(local_index) {
                    *local = value.nullness;
                }
            }
            opcodes::POP => {
                state.stack.pop();
            }
            opcodes::DUP => {
                if let Some(top) = state.stack.last().cloned() {
                    state.stack.push(top);
                }
            }
            opcodes::NEW => {
                state.stack.push(StackValue {
                    nullness: Nullness::NonNull,
                    local: None,
                });
            }
            opcodes::IFNULL | opcodes::IFNONNULL => {
                let value = state.stack.pop().unwrap_or(StackValue {
                    nullness: Nullness::Unknown,
                    local: None,
                });
                if is_last {
                    if let Some(local) = value.local {
                        let (branch_nullness, fallthrough_nullness) =
                            if inst.opcode == opcodes::IFNULL {
                                (Nullness::Nullable, Nullness::NonNull)
                            } else {
                                (Nullness::NonNull, Nullness::Nullable)
                            };
                        branch_refinement = Some(BranchRefinement {
                            local,
                            branch_nullness,
                            fallthrough_nullness,
                        });
                    }
                }
            }
            opcodes::INVOKEVIRTUAL
            | opcodes::INVOKEINTERFACE
            | opcodes::INVOKESPECIAL
            | opcodes::INVOKESTATIC => {
                let call = callsite_by_offset.get(&inst.offset).copied();
                if let Some(call) = call {
                    let arg_count = method_param_count(&call.descriptor)?;
                    for _ in 0..arg_count {
                        state.stack.pop();
                    }
                    if call.kind != CallKind::Static {
                        let receiver = state.stack.pop().unwrap_or(StackValue {
                            nullness: Nullness::Unknown,
                            local: None,
                        });
                        if receiver.nullness == Nullness::Nullable {
                            let message = result_message(format!(
                                "Nullness issue: possible null receiver in call to {}.{}{}",
                                call.owner, call.name, call.descriptor
                            ));
                            let line = method.line_for_offset(inst.offset);
                            let location = method_location_with_line(
                                &class.name,
                                &method.name,
                                &method.descriptor,
                                artifact_uri,
                                line,
                            );
                            results.push(
                                SarifResult::builder()
                                    .message(message)
                                    .locations(vec![location])
                                    .build(),
                            );
                        }
                    }
                    if method_return_kind(&call.descriptor)? == ReturnKind::Reference {
                        let return_nullness =
                            lookup_return_nullness(class_map, call).unwrap_or(Nullness::Unknown);
                        state.stack.push(StackValue {
                            nullness: return_nullness,
                            local: None,
                        });
                    }
                }
            }
            opcodes::ARETURN => {
                let value = state.stack.pop().unwrap_or(StackValue {
                    nullness: Nullness::Unknown,
                    local: None,
                });
                if method.nullness.return_nullness == Nullness::NonNull
                    && value.nullness == Nullness::Nullable
                {
                    let message = result_message(format!(
                        "Nullness issue: {}.{}{} returns null but is @NonNull",
                        class.name, method.name, method.descriptor
                    ));
                    let line = method.line_for_offset(inst.offset);
                    let location = method_location_with_line(
                        &class.name,
                        &method.name,
                        &method.descriptor,
                        artifact_uri,
                        line,
                    );
                    results.push(
                        SarifResult::builder()
                            .message(message)
                            .locations(vec![location])
                            .build(),
                    );
                }
            }
            _ => {}
        }
    }

    Ok(BlockTransfer {
        out_state: state,
        branch_refinement,
        results,
    })
}

fn local_count(method: &Method) -> Result<usize> {
    let mut max_index = 0usize;
    let mut offset = 0usize;
    while offset < method.bytecode.len() {
        let opcode = method.bytecode[offset];
        if opcode == opcodes::ALOAD || opcode == opcodes::ASTORE {
            if let Some(index) = method.bytecode.get(offset + 1) {
                max_index = max_index.max(*index as usize);
            }
        } else if opcode >= opcodes::ALOAD_0 && opcode <= opcodes::ALOAD_3 {
            max_index = max_index.max((opcode - opcodes::ALOAD_0) as usize);
        } else if opcode >= opcodes::ASTORE_0 && opcode <= opcodes::ASTORE_3 {
            max_index = max_index.max((opcode - opcodes::ASTORE_0) as usize);
        }
        let length = crate::scan::opcode_length(&method.bytecode, offset)?;
        offset += length;
    }
    let param_count = method_param_count(&method.descriptor)?;
    let base = if method.access.is_static { 0 } else { 1 };
    Ok(max_index.max(base + param_count).saturating_add(1))
}

fn join_states(left: &State, right: &State) -> State {
    let max_locals = left.locals.len().max(right.locals.len());
    let mut locals = Vec::with_capacity(max_locals);
    for index in 0..max_locals {
        let l = left.locals.get(index).copied().unwrap_or(Nullness::Unknown);
        let r = right
            .locals
            .get(index)
            .copied()
            .unwrap_or(Nullness::Unknown);
        locals.push(join_nullness(l, r));
    }
    let stack = if left.stack.len() == right.stack.len() {
        left.stack
            .iter()
            .zip(right.stack.iter())
            .map(|(l, r)| StackValue {
                nullness: join_nullness(l.nullness, r.nullness),
                local: if l.local == r.local { l.local } else { None },
            })
            .collect()
    } else {
        Vec::new()
    };
    State { locals, stack }
}

fn join_nullness(left: Nullness, right: Nullness) -> Nullness {
    match (left, right) {
        (Nullness::NonNull, Nullness::NonNull) => Nullness::NonNull,
        (Nullness::Nullable, Nullness::Nullable) => Nullness::Nullable,
        _ => Nullness::Unknown,
    }
}

fn lookup_return_nullness(
    class_map: &BTreeMap<String, &Class>,
    call: &crate::ir::CallSite,
) -> Option<Nullness> {
    let class = class_map.get(&call.owner)?;
    let method = class
        .methods
        .iter()
        .find(|method| method.name == call.name && method.descriptor == call.descriptor)?;
    Some(method.nullness.return_nullness)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classpath::resolve_classpath;
    use crate::engine::build_context;
    use crate::ir::{
        BasicBlock, CallKind, CallSite, Class, ControlFlowGraph, Instruction, InstructionKind,
        MethodAccess, MethodNullness,
    };
    use crate::test_harness::{JvmTestHarness, Language, SourceFile};

    fn method_with(
        name: &str,
        descriptor: &str,
        access: MethodAccess,
        nullness: MethodNullness,
        bytecode: Vec<u8>,
        instructions: Vec<Instruction>,
        calls: Vec<CallSite>,
    ) -> Method {
        let end_offset = bytecode.len() as u32;
        Method {
            name: name.to_string(),
            descriptor: descriptor.to_string(),
            access,
            nullness,
            bytecode,
            line_numbers: Vec::new(),
            cfg: ControlFlowGraph {
                blocks: vec![BasicBlock {
                    start_offset: 0,
                    end_offset,
                    instructions,
                }],
                edges: Vec::new(),
            },
            calls,
            string_literals: Vec::new(),
            exception_handlers: Vec::new(),
        }
    }

    fn class_with_methods(name: &str, super_name: Option<&str>, methods: Vec<Method>) -> Class {
        Class {
            name: name.to_string(),
            super_name: super_name.map(str::to_string),
            interfaces: Vec::new(),
            referenced_classes: Vec::new(),
            fields: Vec::new(),
            methods,
            artifact_index: 0,
            is_record: false,
        }
    }

    fn context_for(classes: Vec<Class>) -> AnalysisContext {
        let classpath = resolve_classpath(&classes).expect("classpath build");
        build_context(classes, classpath, &[])
    }

    fn jspecify_stubs() -> Vec<SourceFile> {
        vec![
            SourceFile {
                path: "org/jspecify/annotations/NullMarked.java".to_string(),
                contents: r#"
package org.jspecify.annotations;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.PACKAGE})
public @interface NullMarked {}
"#
                .to_string(),
            },
            SourceFile {
                path: "org/jspecify/annotations/NullUnmarked.java".to_string(),
                contents: r#"
package org.jspecify.annotations;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.PACKAGE})
public @interface NullUnmarked {}
"#
                .to_string(),
            },
            SourceFile {
                path: "org/jspecify/annotations/Nullable.java".to_string(),
                contents: r#"
package org.jspecify.annotations;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE_USE, ElementType.TYPE_PARAMETER})
public @interface Nullable {}
"#
                .to_string(),
            },
            SourceFile {
                path: "org/jspecify/annotations/NonNull.java".to_string(),
                contents: r#"
package org.jspecify.annotations;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE_USE, ElementType.TYPE_PARAMETER})
public @interface NonNull {}
"#
                .to_string(),
            },
            SourceFile {
                path: "org/jspecify/annotations/NullnessUnspecified.java".to_string(),
                contents: r#"
package org.jspecify.annotations;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE_USE, ElementType.TYPE_PARAMETER})
public @interface NullnessUnspecified {}
"#
                .to_string(),
            },
        ]
    }

    fn analyze_with_harness(sources: Vec<SourceFile>) -> crate::engine::EngineOutput {
        let harness = JvmTestHarness::new().expect("JAVA_HOME must be set for harness tests");
        harness
            .compile_and_analyze(Language::Java, &sources, &[])
            .expect("run harness analysis")
    }

    #[test]
    fn nullness_override_reports_return_mismatch() {
        let base_method = Method {
            name: "value".to_string(),
            descriptor: "()Ljava/lang/String;".to_string(),
            access: MethodAccess {
                is_public: true,
                is_static: false,
                is_abstract: false,
            },
            nullness: MethodNullness {
                return_nullness: Nullness::NonNull,
                parameter_nullness: Vec::new(),
            },
            bytecode: Vec::new(),
            line_numbers: Vec::new(),
            cfg: ControlFlowGraph {
                blocks: Vec::new(),
                edges: Vec::new(),
            },
            calls: Vec::new(),
            string_literals: Vec::new(),
            exception_handlers: Vec::new(),
        };
        let override_method = Method {
            name: "value".to_string(),
            descriptor: "()Ljava/lang/String;".to_string(),
            access: MethodAccess {
                is_public: true,
                is_static: false,
                is_abstract: false,
            },
            nullness: MethodNullness {
                return_nullness: Nullness::Nullable,
                parameter_nullness: Vec::new(),
            },
            bytecode: Vec::new(),
            line_numbers: Vec::new(),
            cfg: ControlFlowGraph {
                blocks: Vec::new(),
                edges: Vec::new(),
            },
            calls: Vec::new(),
            string_literals: Vec::new(),
            exception_handlers: Vec::new(),
        };
        let base = class_with_methods("com/example/Base", None, vec![base_method]);
        let derived = class_with_methods(
            "com/example/Derived",
            Some("com/example/Base"),
            vec![override_method],
        );
        let context = context_for(vec![base, derived]);

        let results = NullnessRule.run(&context).expect("nullness rule run");

        assert_eq!(1, results.len());
        let message = results[0].message.text.as_deref().unwrap_or("");
        assert!(message.contains("returns @Nullable but overrides @NonNull"));
    }

    #[test]
    fn nullness_override_reports_parameter_mismatch() {
        let base_method = Method {
            name: "set".to_string(),
            descriptor: "(Ljava/lang/String;)V".to_string(),
            access: MethodAccess {
                is_public: true,
                is_static: false,
                is_abstract: false,
            },
            nullness: MethodNullness {
                return_nullness: Nullness::Unknown,
                parameter_nullness: vec![Nullness::Nullable],
            },
            bytecode: Vec::new(),
            line_numbers: Vec::new(),
            cfg: ControlFlowGraph {
                blocks: Vec::new(),
                edges: Vec::new(),
            },
            calls: Vec::new(),
            string_literals: Vec::new(),
            exception_handlers: Vec::new(),
        };
        let override_method = Method {
            name: "set".to_string(),
            descriptor: "(Ljava/lang/String;)V".to_string(),
            access: MethodAccess {
                is_public: true,
                is_static: false,
                is_abstract: false,
            },
            nullness: MethodNullness {
                return_nullness: Nullness::Unknown,
                parameter_nullness: vec![Nullness::NonNull],
            },
            bytecode: Vec::new(),
            line_numbers: Vec::new(),
            cfg: ControlFlowGraph {
                blocks: Vec::new(),
                edges: Vec::new(),
            },
            calls: Vec::new(),
            string_literals: Vec::new(),
            exception_handlers: Vec::new(),
        };
        let base = class_with_methods("com/example/Base", None, vec![base_method]);
        let derived = class_with_methods(
            "com/example/Derived",
            Some("com/example/Base"),
            vec![override_method],
        );
        let context = context_for(vec![base, derived]);

        let results = NullnessRule.run(&context).expect("nullness rule run");

        assert_eq!(1, results.len());
        let message = results[0].message.text.as_deref().unwrap_or("");
        assert!(message.contains("parameter 0 is @NonNull but overrides @Nullable"));
    }

    #[test]
    fn nullness_flow_reports_returning_null() {
        let method = method_with(
            "value",
            "()Ljava/lang/String;",
            MethodAccess {
                is_public: true,
                is_static: false,
                is_abstract: false,
            },
            MethodNullness {
                return_nullness: Nullness::NonNull,
                parameter_nullness: Vec::new(),
            },
            vec![opcodes::ACONST_NULL, opcodes::ARETURN],
            vec![
                Instruction {
                    offset: 0,
                    opcode: opcodes::ACONST_NULL,
                    kind: InstructionKind::Other(opcodes::ACONST_NULL),
                },
                Instruction {
                    offset: 1,
                    opcode: opcodes::ARETURN,
                    kind: InstructionKind::Other(opcodes::ARETURN),
                },
            ],
            Vec::new(),
        );
        let class = class_with_methods("com/example/ReturnNull", None, vec![method]);
        let context = context_for(vec![class]);

        let results = NullnessRule.run(&context).expect("nullness rule run");

        assert_eq!(1, results.len());
        let message = results[0].message.text.as_deref().unwrap_or("");
        assert!(message.contains("returns null but is @NonNull"));
    }

    #[test]
    fn nullness_flow_reports_nullable_receiver() {
        let method = method_with(
            "invoke",
            "(Ljava/lang/Object;)V",
            MethodAccess {
                is_public: true,
                is_static: true,
                is_abstract: false,
            },
            MethodNullness {
                return_nullness: Nullness::Unknown,
                parameter_nullness: vec![Nullness::Nullable],
            },
            vec![
                opcodes::ALOAD_0,
                opcodes::INVOKEVIRTUAL,
                0x00,
                0x01,
                opcodes::RETURN,
            ],
            vec![
                Instruction {
                    offset: 0,
                    opcode: opcodes::ALOAD_0,
                    kind: InstructionKind::Other(opcodes::ALOAD_0),
                },
                Instruction {
                    offset: 1,
                    opcode: opcodes::INVOKEVIRTUAL,
                    kind: InstructionKind::Other(opcodes::INVOKEVIRTUAL),
                },
                Instruction {
                    offset: 4,
                    opcode: opcodes::RETURN,
                    kind: InstructionKind::Other(opcodes::RETURN),
                },
            ],
            vec![CallSite {
                owner: "com/example/Target".to_string(),
                name: "run".to_string(),
                descriptor: "()V".to_string(),
                kind: CallKind::Virtual,
                offset: 1,
            }],
        );
        let class = class_with_methods("com/example/Caller", None, vec![method]);
        let context = context_for(vec![class]);

        let results = NullnessRule.run(&context).expect("nullness rule run");

        assert_eq!(1, results.len());
        let message = results[0].message.text.as_deref().unwrap_or("");
        assert!(message.contains("possible null receiver"));
    }

    #[test]
    fn nullness_rule_reports_nonnull_return_from_marked_class() {
        let mut sources = jspecify_stubs();
        sources.push(SourceFile {
            path: "com/example/Sample.java".to_string(),
            contents: r#"
package com.example;
import org.jspecify.annotations.NullMarked;
@NullMarked
public class Sample {
    public String value() {
        return null;
    }
}
"#
            .to_string(),
        });

        let output = analyze_with_harness(sources);
        let messages: Vec<String> = output
            .results
            .iter()
            .filter(|result| result.rule_id.as_deref() == Some("NULLNESS"))
            .filter_map(|result| result.message.text.clone())
            .collect();

        assert!(
            messages
                .iter()
                .any(|msg| msg.contains("returns null but is @NonNull"))
        );
    }

    #[test]
    fn nullness_rule_skips_unmarked_class_returning_null() {
        let mut sources = jspecify_stubs();
        sources.push(SourceFile {
            path: "com/example/Sample.java".to_string(),
            contents: r#"
package com.example;
import org.jspecify.annotations.NullUnmarked;
@NullUnmarked
public class Sample {
    public String value() {
        return null;
    }
}
"#
            .to_string(),
        });

        let output = analyze_with_harness(sources);
        let has_nullness = output
            .results
            .iter()
            .any(|result| result.rule_id.as_deref() == Some("NULLNESS"));
        assert!(!has_nullness);
    }

    #[test]
    fn nullness_rule_allows_nullable_return_override() {
        let mut sources = jspecify_stubs();
        sources.push(SourceFile {
            path: "com/example/Sample.java".to_string(),
            contents: r#"
package com.example;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
@NullMarked
public class Sample {
    public @Nullable String value() {
        return null;
    }
}
"#
            .to_string(),
        });

        let output = analyze_with_harness(sources);
        let has_nullness = output
            .results
            .iter()
            .any(|result| result.rule_id.as_deref() == Some("NULLNESS"));
        assert!(!has_nullness);
    }

    #[test]
    fn nullness_rule_reports_explicit_nonnull_return_in_unmarked_class() {
        let mut sources = jspecify_stubs();
        sources.push(SourceFile {
            path: "com/example/Sample.java".to_string(),
            contents: r#"
package com.example;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.NullUnmarked;
@NullUnmarked
public class Sample {
    public @NonNull String value() {
        return null;
    }
}
"#
            .to_string(),
        });

        let output = analyze_with_harness(sources);
        let messages: Vec<String> = output
            .results
            .iter()
            .filter(|result| result.rule_id.as_deref() == Some("NULLNESS"))
            .filter_map(|result| result.message.text.clone())
            .collect();

        assert!(
            messages
                .iter()
                .any(|msg| msg.contains("returns null but is @NonNull"))
        );
    }

    #[test]
    fn nullness_rule_reports_nullable_parameter_receiver() {
        let mut sources = jspecify_stubs();
        sources.push(SourceFile {
            path: "com/example/Sample.java".to_string(),
            contents: r#"
package com.example;
import org.jspecify.annotations.Nullable;
public class Sample {
    public static void use(@Nullable String value) {
        value.toString();
    }
}
"#
            .to_string(),
        });

        let output = analyze_with_harness(sources);
        let messages: Vec<String> = output
            .results
            .iter()
            .filter(|result| result.rule_id.as_deref() == Some("NULLNESS"))
            .filter_map(|result| result.message.text.clone())
            .collect();

        assert!(
            messages
                .iter()
                .any(|msg| msg.contains("possible null receiver"))
        );
    }

    #[test]
    fn nullness_rule_allows_unspecified_parameter() {
        let mut sources = jspecify_stubs();
        sources.push(SourceFile {
            path: "com/example/Sample.java".to_string(),
            contents: r#"
package com.example;
import org.jspecify.annotations.NullnessUnspecified;
public class Sample {
    public static void use(@NullnessUnspecified String value) {
        value.toString();
    }
}
"#
            .to_string(),
        });

        let output = analyze_with_harness(sources);
        let has_nullness = output
            .results
            .iter()
            .any(|result| result.rule_id.as_deref() == Some("NULLNESS"));
        assert!(!has_nullness);
    }

    #[test]
    fn nullness_rule_reports_override_mismatch_from_annotations() {
        let mut sources = jspecify_stubs();
        sources.extend(vec![
            SourceFile {
                path: "com/example/Base.java".to_string(),
                contents: r#"
package com.example;
import org.jspecify.annotations.NonNull;
public class Base {
    public @NonNull String value() {
        return "ok";
    }
}
"#
                .to_string(),
            },
            SourceFile {
                path: "com/example/Derived.java".to_string(),
                contents: r#"
package com.example;
import org.jspecify.annotations.Nullable;
public class Derived extends Base {
    @Override
    public @Nullable String value() {
        return null;
    }
}
"#
                .to_string(),
            },
        ]);

        let output = analyze_with_harness(sources);
        let messages: Vec<String> = output
            .results
            .iter()
            .filter(|result| result.rule_id.as_deref() == Some("NULLNESS"))
            .filter_map(|result| result.message.text.clone())
            .collect();

        assert!(
            messages
                .iter()
                .any(|msg| msg.contains("returns @Nullable but overrides @NonNull"))
        );
    }
}
