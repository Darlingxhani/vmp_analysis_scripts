#!/usr/bin/env python3
# Script to generate draw.io-compatible XML flowchart from OllyDbg run trace
import sys
import re
from xml.sax.saxutils import escape
from collections import defaultdict

# 支持的跳转指令列表，包括常见别名
JUMP_INSTRS = {
    "jmp", "je", "jne", "jg", "jl", "jge", "jle", "jo", "jno", "js", "jns",
    "jp", "jnp", "jz", "jnz", "jb", "jae", "jbe", "ja", "jnbe",
    "jcxz", "jecxz", "jrcxz", "loop", "loope", "loopne",
    "jpe", "jpo"
}
CALL_INSTRS = {"call"}
RET_INSTRS = {"ret", "retn"}

# 指令定义
class Instruction:
    @staticmethod
    def parseInstruction(line):
        if len(line.split('\t')) >= 4:
            instruction = Instruction(line)
            return instruction
        else:
            return None

    def __init__(self, line):
        parts = line.split('\t')
        if len(parts) >= 4:
            self.address = parts[0].strip()
            self.bytes = parts[1].replace(" ", "")
            self.command = parts[2].strip()

            register_info = parts[3].strip()
            register_split = register_info.split(' ')
            if len(register_split) == 18:
                self.register = {
                    'eax': register_split[1],
                    'ebx': register_split[3],
                    'ecx': register_split[5],
                    'edx': register_split[7],
                    'esi': register_split[9],
                    'edi': register_split[11],
                    'ebp': register_split[13],
                    'esp': register_split[15],
                    'eflags': register_split[17]
                }


# 指令块定义
class BasicBlock:
    def __init__(self, instructions):
        self.instructions = instructions
        self.bytes = ""
        self.prev_blocks = set()  # 前驱块索引
        self.next_blocks = set()    # 后继块索引
        self.start_address = instructions[0].address if instructions else None
        self.block_name = "block_" + self.start_address.replace("0x", "")
        self.recognize_name = ""
        self.block_bgcolor = "gray"
        self.block_fontcolor = "black"
        self.bytes = "".join(ins.bytes for ins in instructions)

        # 记录每个块在指令执行流里面出现的顺序，可能会多次出现
        self.appearance_order = set()

    
    def __repr__(self):
        return f"Block({self.start_address}, prev_blocks={self.prev_blocks}, next_blocks={self.next_blocks})"
    
    def add_prev(self, prev_idx: int):
        self.prev_blocks.add(prev_idx)

    def add_prev_set(self, prev_idx_set: set):
        self.prev_blocks = self.prev_blocks.union(prev_idx_set)
    
    def add_next(self, next_idx: int):
        self.next_blocks.add(next_idx)

    def add_next_set(self, next_idx_set: set):
        self.next_blocks = self.next_blocks.union(next_idx_set)

    def get_prev(self):
        return self.prev_blocks
    
    def get_next(self):
        return self.next_blocks

    def get_appearance_order(self):
        return self.appearance_order
    
    def add_appearance_order(self, other_apperance_set: set):
        self.appearance_order = self.appearance_order.union(other_apperance_set)





def parse_trace_file(path):
    print("[*] Parsing trace file...")
    lines = open(path, 'r', encoding='utf-8', errors='ignore').read().splitlines()[1:]
    instructions = []
    for i, line in enumerate(lines):
        ins = Instruction.parseInstruction(line)
        if ins is not None:
            instructions.append(ins)
    return instructions


def classify_opcode(command):
    op = command.lower().split()[0]
    if op in JUMP_INSTRS:
        return 'jump'
    if op in CALL_INSTRS:
        return 'call'
    if op in RET_INSTRS:
        return 'ret'
    return 'other'


def split_into_basic_blocks(entries):
    leaders = set()
    targets = set()
    blocks = []

    # 识别领导块
    for i, entry in enumerate(entries):
        op_type = classify_opcode(entry.command)
        if op_type in {'jump', 'call'}:
            match = re.search(r'0x[0-9A-Fa-f]+|[0-9A-Fa-f]{6,8}', entry.command)
            if match:
                raw = match.group(0)
                addr = raw.upper().lstrip('0X')
                targets.add(addr)
            if i + 1 < len(entries):
                leaders.add(entries[i+1].address)
        elif op_type == 'ret':
            if i + 1 < len(entries):
                leaders.add(entries[i+1].address)

    leaders |= targets
    if entries:
        leaders.add(entries[0].address)

    # 创建基本块
    current_block_instructions = []
    blocks = []
    
    for entry in entries:
        if entry.address in leaders:
            if current_block_instructions:
                new_block = BasicBlock(instructions = current_block_instructions)
                new_block.appearance_order.add(len(blocks))
                blocks.append(new_block)
                current_block_instructions = []
            current_block_instructions.append(entry)
        else:
            current_block_instructions.append(entry)
    
    if current_block_instructions:
        new_block = BasicBlock(instructions = current_block_instructions)
        new_block.appearance_order.add(len(blocks))
        blocks.append(new_block)
    
    return blocks


def summarize_block(block):
    return "\n".join(f"{e.address.zfill(8)} {e.command}" for e in block)


def extract_edges(blocks):
    edges = []
    addr_to_block = {blk[0].address: idx for idx, blk in enumerate(blocks)}
    for idx, blk in enumerate(blocks):
        last = blk[-1]
        op_type = classify_opcode(last.command)
        if op_type == 'jump':
            m = re.search(r'0x[0-9A-Fa-f]+|[0-9A-Fa-f]{6,8}', last.command)
            if m:
                tgt = m.group(0).upper().lstrip('0X')
                if tgt in addr_to_block:
                    edges.append((idx, addr_to_block[tgt]))
        if op_type != 'jump' and idx + 1 < len(blocks):
            edges.append((idx, idx + 1))
    return edges


# 第二个参数用来描述blocks中的代码块是否是按顺序执行的
def build_control_flow_graph(blocks, is_order, origin_instruction_order):
    # 创建地址到块索引的映射
    addr_to_index = {}
    for index, block in enumerate(blocks):
        addr_to_index[block.start_address] = index
    
    # 如果是按顺序执行的块，则需要添加顺序执行边
    if is_order:
        for i in range(len(blocks)-1):
            blocks[i].add_next(i+1)
            blocks[i+1].add_prev(i)
    else:
        # 否则，如果代码块A的最后一条指令地址和代码块B的第一条指令地址在原始指令序列里连续出现过
        # 说明两个代码块存在连接关系
        # 预处理：构建指令对字典
        successor_dict = {}
        for i in range(len(origin_instruction_order) - 1):
            current_addr = origin_instruction_order[i]
            next_addr = origin_instruction_order[i + 1]
            if current_addr not in successor_dict:
                successor_dict[current_addr] = set()
            successor_dict[current_addr].add(next_addr)
        
        # 检查每个块的最后一个指令可能的后续块
        for index, block in enumerate(blocks):
            last_addr = block.instructions[-1].address
            if last_addr in successor_dict:
                for next_addr in successor_dict[last_addr]:
                    if next_addr in addr_to_index.keys():
                        other_index = addr_to_index[next_addr]
                        if index != other_index:
                            # 构建连接关系
                            block.add_next(other_index)
                            other_block = blocks[other_index]
                            other_block.add_prev(index)


    # 添加跳转边
    for i, block in enumerate(blocks):
        last_instr = block.instructions[-1].command
        op_type = classify_opcode(last_instr)
        
        if op_type == 'jump' or op_type == 'call':
            match = re.search(r'0x[0-9A-Fa-f]+|[0-9A-Fa-f]{6,8}', last_instr)
            if match:
                target = match.group(0).upper()
                if target in addr_to_index:
                    target_idx = addr_to_index[target]
                    block.add_next(target_idx)
                    blocks[target_idx].add_prev(i)
    
    return blocks


def merge_serial_blocks(blocks, block_counts):
    """安全合并串行代码块"""
    merged_blocks = []
    merged_blocks_count = []         # 合并之后的块出现的次数
    current_merge = []
    merged_indices = set()
    
    for i in range(len(blocks)):
        if i in merged_indices:
            continue
            
        # 开始新的合并块
        current_merge = [blocks[i]]
        merged_indices.add(i)
        
        # 检查是否可以继续合并
        current_idx = i
        can_merge = True
        
        while can_merge:
            # 检查当前块只有唯一后继
            if len(blocks[current_idx].next_blocks) != 1:
                can_merge = False
                break
                
            next_idx = next(iter(blocks[current_idx].next_blocks))
            
            # 检查后继块只有唯一前驱
            if len(blocks[next_idx].prev_blocks) != 1:
                can_merge = False
                break
                
            # 检查后继块的前驱是否只有当前块
            if blocks[next_idx].prev_blocks != {current_idx}:
                can_merge = False
                break

            # 对于VMP3.x版本，如果代码块尾部是[jmp 寄存器]或者[push 寄存器 + ret]，则不要合并
            jmp_register_list = ["jmp eax", "jmp ebx", "jmp ecx", "jmp edx", "jmp ebp", "jmp esp", "jmp esi", "jmp edi"]
            if blocks[current_idx].instructions[-1].command in jmp_register_list:
                can_merge = False
                break
            if len(blocks[current_idx].instructions) >= 2 and blocks[current_idx].instructions[-2].command in jmp_register_list and blocks[current_idx].instructions[-1].command in ["ret", "retn"]:
                can_merge = False
                break
                
            # 所有条件满足，可以合并
            current_merge.append(blocks[next_idx])
            merged_indices.add(next_idx)
            current_idx = next_idx
    
        # 创建合并后的块
        merged_instructions = []
        for block in current_merge:
            merged_instructions.extend(block.instructions)
        
        merged_block = BasicBlock(merged_instructions)
        merged_block.appearance_order = current_merge[0].appearance_order   # 合并后的块出现次序用合并块的第一个子块的顺序即可
        merged_blocks.append(merged_block)
        merged_blocks_count.append(block_counts[current_idx])
    
    # 处理未合并的块
    for i in range(len(blocks)):
        if i not in merged_indices:
            merged_blocks.append(blocks[i])
    
    return merged_blocks, merged_blocks_count


def summarize_block_with_count(block, count):
    header = f"[{count} times]"
    lines = [f"{x.address} {x.command}" for x in block.instructions]
    return "\n".join([header] + lines)


from xml.sax.saxutils import escape

def generate_dot_file(blocks, block_counts, output_file):
    """
    生成DOT文件，优化显示：
    - 执行次数>1的块标题：红底白字
    - 每行汇编指令的助记符：蓝色
    - 地址：灰色右对齐
    """
    with open(output_file, 'w', encoding='utf-8') as f:
        # DOT文件头部设置
        f.write('digraph control_flow {\n')
        f.write('  rankdir="TB";\n')
        f.write('  node [shape=none, margin=0, fontname="Courier"];\n')
        f.write('  edge [fontsize=10];\n\n')

        for idx, block in enumerate(blocks):
            count = block_counts[idx]
            
            # 根据是否识别出代码块名称设定不同的颜色
            header_bgcolor = block.block_bgcolor
            header_fontcolor = block.block_fontcolor
            
            # 构建HTML表格
            label = ['<<table border="0" cellborder="1" cellspacing="0">']
            label.append(
                f'<tr><td colspan="2" align="center" bgcolor="{header_bgcolor}">'
                f'<font color="{header_fontcolor}"><b>[ID: {idx}] {block.recognize_name if block.recognize_name != "" else block.block_name} (Executed: {count} time{"s" if count > 1 else ""})</b></font>'
                f'</td></tr>'
            )
            # 展示字节码
            # label.append(
            #     f'<tr><td colspan="2" align="left" balign="left">'
            #     f'<font color="#1E90FF">{escape(block.bytes)}</font>'
            #     f'</td></tr>'
            # )
            
            # 处理每条指令（默认助记符蓝色）
            ins_count = 0
            for inst in block.instructions:
                ins_count = ins_count + 1
                # 分割助记符和操作数（第一个空格前为助记符）
                parts = inst.command.split(maxsplit=1)
                mnemonic = escape(parts[0]) if parts else ""
                operands = escape(parts[1]) if len(parts) > 1 else " "

                address_color = "#333333"
                mnemonic_color = "#1E90FF"
                operands_color = "#333333"

                # 如果出现ESI寄存器相关的操作，标红显示
                if "esi" in operands:
                    address_color = "#FF0000"
                    mnemonic_color = "#FF0000"
                    operands_color = "#FF0000"

                # 如果出现ESP寄存器相关的操作，标红显示
                if "esp" in operands and "ptr" in operands:
                    address_color = "#FF5900"
                    mnemonic_color = "#FF5900"
                    operands_color = "#FF5900"
                
                # 如果出现EDI寄存器相关的操作，标黄显示
                if "edi" in operands:
                    address_color = "#FF0BB6"
                    mnemonic_color = "#FF0BB6"
                    operands_color = "#FF0BB6"

                # 如果出现EBP寄存器相关的操作，标黄显示
                if "ebp" in operands and "ptr" in operands:
                    address_color = "#C30FEB"
                    mnemonic_color = "#C30FEB"
                    operands_color = "#C30FEB"
                
                # 如果出现无效的跳转，将其置灰
                if mnemonic in CALL_INSTRS or (mnemonic in JUMP_INSTRS and ins_count != len(block.instructions)):
                    address_color = "#CCCCCC"
                    mnemonic_color = "#CCCCCC"
                    operands_color = "#CCCCCC"
                
                label.append(
                    f'<tr>'
                    f'<td align="right">'
                        f'<font color="{address_color}">{inst.address.zfill(8)}</font>'
                    f'</td>'
                    f'<td align="left">'
                        f'<font color="{mnemonic_color}">{mnemonic}</font>&nbsp;'
                        f'<font color="{operands_color}">{operands}</font>'
                    f'</td>'
                    f'</tr>'
                )

            
            label.append('</table>>')
            f.write(f'  block_{idx} [label={"".join(label)}];\n')
        
        # 生成所有边（带跳转类型标记）
        for src_idx, block in enumerate(blocks):
            for dst_idx in block.next_blocks:
                last_instr = block.instructions[-1].command.lower()
                
                # 判断边类型
                if any(last_instr.startswith(j) for j in ['ret', 'retn']):
                    # 返回边（红色）
                    f.write(f'  block_{src_idx} -> block_{dst_idx} [color="red", label="RET"];\n')
                elif any(last_instr.startswith(j) for j in ['call']):
                    # 调用边（蓝色）
                    f.write(f'  block_{src_idx} -> block_{dst_idx} [color="blue", label="CALL"];\n')
                elif any(last_instr.startswith(j) for j in ['jmp']):
                    # 无条件跳转（黑色实线）
                    f.write(f'  block_{src_idx} -> block_{dst_idx} [penwidth=2];\n')
                elif any(last_instr.startswith(j) for j in ['je', 'jne', 'jg', 'jl', 'jge', 'jle']):
                    # 条件跳转（绿色虚线）
                    f.write(f'  block_{src_idx} -> block_{dst_idx} [color="green", style="dashed", label="Cond"];\n')
                else:
                    # 顺序执行（默认黑色）
                    f.write(f'  block_{src_idx} -> block_{dst_idx};\n')
        
        f.write('}\n')
    
    print(f"[*] Full DOT file written to {output_file}")


def deduplicate_blocks(blocks):
    """去重并记录每个唯一块的出现次数"""
    unique_blocks = []
    block_map = {}
    block_counts = defaultdict(int)

    # 去重前的索引到去重后的索引映射
    origin_index_to_unique_index = {}
    
    for origin_index, block in enumerate(blocks):
        # 创建块的签名（地址序列）
        signature = tuple(inst.address for inst in block.instructions)
        
        if signature not in block_map:
            block_map[signature] = len(unique_blocks)
            unique_blocks.append(block)
        
        unique_idx = block_map[signature]
        origin_index_to_unique_index[origin_index] = unique_idx
        block_counts[unique_idx] += 1

        # 把相同块的前驱与后继节点信息统一合并记录，还要将出现的顺序也合并
        if block_counts[unique_idx] != 1:
            unique_blocks[unique_idx].add_prev_set(block.get_prev())
            unique_blocks[unique_idx].add_next_set(block.get_next())
            unique_blocks[unique_idx].add_appearance_order(block.get_appearance_order())
    
    # 因为已经去重了，原来block中记录的前驱后继索引信息也要变更为去重之后的新索引
    for unique_block in unique_blocks:
        new_prev_set = set()
        for old_prev_idx in unique_block.prev_blocks:
            new_prev_idx = origin_index_to_unique_index[old_prev_idx]
            new_prev_set.add(new_prev_idx)
        unique_block.prev_blocks = new_prev_set

        new_next_set = set()
        for old_next_idx in unique_block.next_blocks:
            new_next_idx = origin_index_to_unique_index[old_next_idx]
            new_next_set.add(new_next_idx)
        unique_block.next_blocks = new_next_set
    
    return unique_blocks, origin_index_to_unique_index, block_counts


def save_blocks_txt(blocks, path):
    """保存代码块到文本文件"""
    with open(path, "w", encoding="utf-8") as f:
        for i, b in enumerate(blocks):
            f.write(f"--- Basic Block {i} ---\n")
            f.write(f"bytes: {b.bytes}\n")
            for apperance in b.get_appearance_order():
                f.write(f"出现次序：{apperance}\n")

            for inst in b.instructions:
                f.write(f"{inst.address.zfill(8)} {inst.bytes.ljust(20)} {inst.command}\n")
            f.write("\n")
    print(f"[*] Segments written to {path}")


# 对合并后的块进行重新排序
def reorder_merged_blocks(merged_blocks):

    # 先提取原来所有块所有出现的次序
    origin_order_map = dict()
    for block in merged_blocks:
        for order in block.get_appearance_order():
            origin_order_map[order] = block

    from collections import OrderedDict
    origin_order_map = OrderedDict(sorted(origin_order_map.items()))

    # 将代码块出现是顺序记录到文件中
    with open("block_order.txt", "w", encoding="utf-8") as f:
        f.write(f"--- Block Apperance Order ---\n")
        for order in origin_order_map.keys():
            f.write(f"{origin_order_map[order].block_name}\n")

    
    # 准备进行重排序
    new_order = 1
    order_transform_map = dict()
    for origin_order in origin_order_map.keys():
        order_transform_map[origin_order] = new_order
        new_order = new_order + 1

    # 修改为重新排序之后的值
    for block in merged_blocks:
        new_order_set = set()
        for order in block.get_appearance_order():
            new_order_set.add(order_transform_map[order])
        block.appearance_order = new_order_set


if __name__ == '__main__':
    entries = parse_trace_file("run_trace_vmp.3.5.0.txt")
    blocks = split_into_basic_blocks(entries)
    blocks = build_control_flow_graph(blocks, True, None) # 第一次构建去重合并前的原始控制流转移关系

    # 构建原始指令流地址序列
    origin_instruction_order = []
    for e in entries:
        origin_instruction_order.append(e.address)
    
    print(f"原始代码块数量: {len(blocks)}")
    save_blocks_txt(blocks, "rtrace_blocks_full.txt")
    
    # 去重处理
    unique_blocks, origin_index_to_unique_index, block_counts = deduplicate_blocks(blocks)
    print(f"去重后代码块数量: {len(unique_blocks)}")
    save_blocks_txt(unique_blocks, "rtrace_blocks_dedup.txt")

    # 合并串行块
    merged_blocks, merged_blocks_count = merge_serial_blocks(unique_blocks, block_counts)

    # 重新为合并之后的块构建控制流转移关系
    build_control_flow_graph(merged_blocks, False, origin_instruction_order)

    # 重新为合并之后的块设定出现的次序（因为很多块合并之后，顺序需要调整，把顺序数字调小，便于分析）
    reorder_merged_blocks(merged_blocks)
    print(f"合并后代码块数量: {len(merged_blocks)}")
    save_blocks_txt(merged_blocks, "rtrace_blocks_merged.txt")
    
    
    # 生成图表
    generate_dot_file(merged_blocks, merged_blocks_count, "rtrace_graphviz.dot")