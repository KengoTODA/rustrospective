use std::collections::BTreeSet;

use anyhow::{Context, Result};

use crate::ir::{BasicBlock, ControlFlowGraph, EdgeKind, FlowEdge, Instruction};
use crate::opcodes;

/// Build a control flow graph from bytecode instructions.
pub(crate) fn build_cfg(
    code: &[u8],
    instructions: &[Instruction],
    handlers: &[u32],
) -> Result<ControlFlowGraph> {
    let mut leaders = BTreeSet::new();
    leaders.insert(0u32);
    for handler in handlers {
        leaders.insert(*handler);
    }
    for inst in instructions {
        if let Some(targets) = branch_targets(code, inst.offset as usize)? {
            for target in targets {
                leaders.insert(target as u32);
            }
            let next = inst.offset + opcode_length(code, inst.offset as usize)? as u32;
            leaders.insert(next);
        }
        if is_exit_opcode(inst.opcode) {
            let next = inst.offset + opcode_length(code, inst.offset as usize)? as u32;
            leaders.insert(next);
        }
    }

    let mut leader_list: Vec<u32> = leaders.into_iter().collect();
    leader_list.retain(|offset| *offset < code.len() as u32);
    leader_list.sort();
    leader_list.dedup();

    let mut blocks = Vec::new();
    for window in leader_list.windows(2) {
        let start = window[0];
        let end = window[1];
        let block_instructions = instructions
            .iter()
            .filter(|inst| inst.offset >= start && inst.offset < end)
            .cloned()
            .collect();
        blocks.push(BasicBlock {
            start_offset: start,
            end_offset: end,
            instructions: block_instructions,
        });
    }
    if let Some(last_start) = leader_list.last().copied() {
        let block_instructions = instructions
            .iter()
            .filter(|inst| inst.offset >= last_start)
            .cloned()
            .collect();
        blocks.push(BasicBlock {
            start_offset: last_start,
            end_offset: code.len() as u32,
            instructions: block_instructions,
        });
    }

    let mut edges = Vec::new();
    for block in &blocks {
        let Some(last_inst) = block.instructions.last() else {
            continue;
        };
        if let Some(targets) = branch_targets(code, last_inst.offset as usize)? {
            for target in targets {
                edges.push(FlowEdge {
                    from: block.start_offset,
                    to: target as u32,
                    kind: EdgeKind::Branch,
                });
            }
            if !is_unconditional_branch(last_inst.opcode) {
                if let Some(next) = next_block_start(&blocks, block.end_offset) {
                    edges.push(FlowEdge {
                        from: block.start_offset,
                        to: next,
                        kind: EdgeKind::FallThrough,
                    });
                }
            }
        } else if !is_exit_opcode(last_inst.opcode) {
            if let Some(next) = next_block_start(&blocks, block.end_offset) {
                edges.push(FlowEdge {
                    from: block.start_offset,
                    to: next,
                    kind: EdgeKind::FallThrough,
                });
            }
        }
    }

    Ok(ControlFlowGraph { blocks, edges })
}

fn next_block_start(blocks: &[BasicBlock], offset: u32) -> Option<u32> {
    blocks
        .iter()
        .find(|block| block.start_offset == offset)
        .map(|block| block.start_offset)
}

fn is_exit_opcode(opcode: u8) -> bool {
    matches!(
        opcode,
        opcodes::IRETURN
            | opcodes::LRETURN
            | opcodes::FRETURN
            | opcodes::DRETURN
            | opcodes::ARETURN
            | opcodes::RETURN
            | opcodes::ATHROW
    )
}

fn is_unconditional_branch(opcode: u8) -> bool {
    matches!(
        opcode,
        opcodes::GOTO | opcodes::JSR | opcodes::GOTO_W | opcodes::JSR_W
    )
}

fn branch_targets(code: &[u8], offset: usize) -> Result<Option<Vec<u16>>> {
    let opcode = code[offset];
    let targets = match opcode {
        0x99..=0xa6 | opcodes::GOTO | opcodes::JSR | 0xc6 | 0xc7 => {
            let branch = read_i16(code, offset + 1)?;
            let target = offset as i32 + branch as i32;
            vec![target as u16]
        }
        opcodes::GOTO_W | opcodes::JSR_W => {
            let branch = read_i32(code, offset + 1)?;
            let target = offset as i32 + branch as i32;
            vec![target as u16]
        }
        0xaa => tableswitch_targets(code, offset)?,
        0xab => lookupswitch_targets(code, offset)?,
        _ => return Ok(None),
    };
    Ok(Some(targets))
}

fn tableswitch_targets(code: &[u8], offset: usize) -> Result<Vec<u16>> {
    let padding = padding(offset);
    let base = offset + 1 + padding;
    let default = read_i32(code, base)?;
    let low = read_i32(code, base + 4)?;
    let high = read_i32(code, base + 8)?;
    let count = high
        .checked_sub(low)
        .and_then(|v| v.checked_add(1))
        .context("invalid tableswitch range")?;
    let mut targets = Vec::new();
    targets.push((offset as i32 + default) as u16);
    let mut idx = base + 12;
    for _ in 0..count {
        let target = read_i32(code, idx)?;
        targets.push((offset as i32 + target) as u16);
        idx += 4;
    }
    Ok(targets)
}

fn lookupswitch_targets(code: &[u8], offset: usize) -> Result<Vec<u16>> {
    let padding = padding(offset);
    let base = offset + 1 + padding;
    let default = read_i32(code, base)?;
    let npairs = read_i32(code, base + 4)?;
    let mut targets = Vec::new();
    targets.push((offset as i32 + default) as u16);
    let mut idx = base + 8;
    for _ in 0..npairs {
        let target = read_i32(code, idx + 4)?;
        targets.push((offset as i32 + target) as u16);
        idx += 8;
    }
    Ok(targets)
}

fn opcode_length(code: &[u8], offset: usize) -> Result<usize> {
    crate::scan::opcode_length(code, offset)
}

fn padding(offset: usize) -> usize {
    crate::scan::padding(offset)
}

fn read_i16(code: &[u8], offset: usize) -> Result<i16> {
    let value = crate::scan::read_u16(code, offset)?;
    Ok(i16::from_be_bytes(value.to_be_bytes()))
}

fn read_i32(code: &[u8], offset: usize) -> Result<i32> {
    let value = crate::scan::read_u32(code, offset)?;
    Ok(i32::from_be_bytes(value.to_be_bytes()))
}
