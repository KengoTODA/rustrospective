use anyhow::Result;
use serde_sarif::sarif::Result as SarifResult;

use crate::engine::AnalysisContext;
use crate::ir::Instruction;
use crate::opcodes;
use crate::rules::{method_location, result_message, Rule, RuleMetadata};

/// Rule that detects empty catch blocks.
pub(crate) struct EmptyCatchRule;

impl Rule for EmptyCatchRule {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "EMPTY_CATCH",
            name: "Empty catch block",
            description: "Catch blocks with no meaningful instructions",
        }
    }

    fn run(&self, context: &AnalysisContext) -> Result<Vec<SarifResult>> {
        let mut results = Vec::new();
        for class in &context.classes {
            for method in &class.methods {
                for handler in &method.exception_handlers {
                    let Some(block) = method
                        .cfg
                        .blocks
                        .iter()
                        .find(|block| block.start_offset == handler.handler_pc)
                    else {
                        continue;
                    };
                    if is_empty_handler(block.instructions.as_slice()) {
                        let message = result_message(format!(
                            "Empty catch block in {}.{}{}",
                            class.name, method.name, method.descriptor
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

fn is_empty_handler(instructions: &[Instruction]) -> bool {
    if instructions.is_empty() {
        return true;
    }
    instructions
        .iter()
        .all(|inst| is_trivial_opcode(inst.opcode))
}

fn is_trivial_opcode(opcode: u8) -> bool {
    matches!(
        opcode,
        opcodes::NOP
            | opcodes::GOTO
            | opcodes::JSR
            | opcodes::IRETURN
            | opcodes::LRETURN
            | opcodes::FRETURN
            | opcodes::DRETURN
            | opcodes::ARETURN
            | opcodes::RETURN
            | opcodes::ATHROW
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classpath::resolve_classpath;
    use crate::engine::build_context;
    use crate::ir::{
        BasicBlock, Class, ControlFlowGraph, ExceptionHandler, Instruction, InstructionKind,
        Method, MethodAccess,
    };

    fn default_access() -> MethodAccess {
        MethodAccess {
            is_public: true,
            is_static: false,
            is_abstract: false,
        }
    }

    fn method_with(
        name: &str,
        descriptor: &str,
        cfg: ControlFlowGraph,
        handlers: Vec<ExceptionHandler>,
    ) -> Method {
        Method {
            name: name.to_string(),
            descriptor: descriptor.to_string(),
            access: default_access(),
            bytecode: vec![0],
            cfg,
            calls: Vec::new(),
            string_literals: Vec::new(),
            exception_handlers: handlers,
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
    fn empty_catch_rule_reports_trivial_handler() {
        let block = BasicBlock {
            start_offset: 0,
            end_offset: 1,
            instructions: vec![Instruction {
                offset: 0,
                opcode: opcodes::NOP,
                kind: InstructionKind::Other(opcodes::NOP),
            }],
        };
        let cfg = ControlFlowGraph {
            blocks: vec![block],
            edges: Vec::new(),
        };
        let handlers = vec![ExceptionHandler {
            start_pc: 0,
            end_pc: 1,
            handler_pc: 0,
            catch_type: None,
        }];
        let method = method_with("handle", "()V", cfg, handlers);
        let classes = vec![class_with_methods("com/example/App", vec![method])];
        let context = context_for(classes);

        let results = EmptyCatchRule.run(&context).expect("empty catch rule run");

        assert_eq!(1, results.len());
    }

    #[test]
    fn empty_catch_rule_ignores_non_trivial_handler() {
        let block = BasicBlock {
            start_offset: 0,
            end_offset: 1,
            instructions: vec![Instruction {
                offset: 0,
                opcode: opcodes::INVOKESTATIC,
                kind: InstructionKind::Other(opcodes::INVOKESTATIC),
            }],
        };
        let cfg = ControlFlowGraph {
            blocks: vec![block],
            edges: Vec::new(),
        };
        let handlers = vec![ExceptionHandler {
            start_pc: 0,
            end_pc: 1,
            handler_pc: 0,
            catch_type: None,
        }];
        let method = method_with("handle", "()V", cfg, handlers);
        let classes = vec![class_with_methods("com/example/App", vec![method])];
        let context = context_for(classes);

        let results = EmptyCatchRule.run(&context).expect("empty catch rule run");

        assert!(results.is_empty());
    }
}
