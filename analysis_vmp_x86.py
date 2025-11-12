# 分析VMP虚拟指令
import re
import os
from analysis_pin_runtrace_file_x86 import *

class Handler:
    def __init__(self):
        self.name = ""
        self.bgcolor = "#336EE4"
        self.fontcolor = "#e0e0e0"
        self.signature_instructions = []               # 特征指令块
        self.signature_instructions_has_order = False   # 标识特征指令是否有序，默认无序

    def get_name(self):
        return self.name

    ## 识别指令块
    ## 识别原理：根据关键指令特征来识别
    def recognize(self, block: BasicBlock):
        # 先检查结尾是不是jmp esi或者push esi; ret指令，过滤一下是否是VMP3的Handler
        if len(block.instructions) < 5:
            return False
        # if block.instructions[-1].command[:3] != "jmp" and block.instructions[-1].command != "ret":
        #     return False
        
        # 先把当前要判断的块的指令拼接在一起
        all_instructions = "\n".join(ins.command for ins in block.instructions)
        
        # 开始遍历特征指令块
        for signature_block in self.signature_instructions:
            match_target = all_instructions
            match_count = 0
            for signature_ins in signature_block:
                # 只要有一条特征指令没找到，就退出这个特征块，匹配下一个块
                # 匹配上也需要检查位置各条特征指令出现的顺序，顺序不对也不行
                match = re.search(signature_ins, match_target)
                if not match:
                    break
                else:
                    match_count = match_count + 1
                
                # 如果特征指令块里的指令有序，则更新待匹配的目标为后续部分
                if self.signature_instructions_has_order:
                    match_target = match_target[match.end():]
            
            # 如果有一个块的特征指令全部匹配上，则匹配成功
            if match_count == len(signature_block):
                return True
        
        return False
    
    # 获取指令参数
    def get_parameter(self, block: BasicBlock):
        return ""
        

class Handler_vPushImm4(Handler):

    def __init__(self):
        super().__init__()
        self.name = "vPushImm4"
        self.signature_instructions_has_order = True
        self.signature_instructions = [
            [
                r"mov\s+(e[a-z]{2}),\s*dword\s*ptr\s*\[edi\]",
                r"lea\s*(ebp|esi),\s*ptr\s*\[(e[a-z]{2})\-0x4\]",
                r"mov\s+dword\s*ptr\s*\[(ebp|esi)\],\s*(e[a-z]{2})"
            ],
            [
                r"mov\s+(e[a-z]{2}),\s*dword\s*ptr\s*\[edi\]",
                r"sub\s*(ebp|esi),\s*0x4",
                r"mov\s*dword\s*ptr\s*\[(ebp|esi)\],\s*(e[a-z]{2})"
            ]
        ]
    
    def get_parameter(self, block: BasicBlock):
        for ins in block.instructions:
            match = re.search(r"mov\s*dword\s*ptr\s*\[(ebp|esi)\],\s*(e[a-z]{2})", ins.command)
            if match:
                register = match.group(2)
                param = "0x" + ins.register[register]
                return param
        return ""


class Handler_vPushImm2(Handler):

    def __init__(self):
        super().__init__()
        self.name = "vPushImm2"
        self.signature_instructions = [
            [
                r"movzx\s+(e[a-z]{2}),\s*word\s*ptr\s*\[edi\]",
                r"lea\s*(ebp|esi),\s*ptr\s*\[(e[a-z]{2})\-0x2\]",
                r"mov\s+word\s*ptr\s*\[(ebp|esi)\],\s*([a-z]{2})"
            ],
            [
                r"movzx\s+(e[a-z]{2}),\s*word\s*ptr\s*\[edi\]",
                r"sub\s*(ebp|esi),\s*0x2",
                r"mov\s*word\s*ptr\s*\[(ebp|esi)\],\s*([a-z]{2})"
            ]
        ]
    
    def get_parameter(self, block: BasicBlock):
        for ins in block.instructions:
            match = re.search(r"mov\s*word\s*ptr\s*\[(ebp|esi)\],\s*([a-z]{2})", ins.command)
            if match:
                register = match.group(2)
                param = "0x" + ins.register["e"+register]
                return param
        return ""

class Handler_vPushReg4(Handler):

    def __init__(self):
        super().__init__()
        self.name = "vPushReg4"
        self.signature_instructions = [
            [
                r"movzx\s*(e[a-z]{2}),\s*byte\s*ptr\s*\[edi\]",
                r"mov\s*(e[a-z]{2}),\s*dword\s*ptr\s*\[esp\+(e[a-z]{2})\*1\]",
                r"lea\s*(ebp|esi),\s*ptr\s*\[(ebp|esi)\-0x4\]",
                r"mov\s*dword\s*ptr\s*\[(ebp|esi)\],\s*(e[a-z]{2})"
            ],
            [
                r"movzx\s*(e[a-z]{2}),\s*byte\s*ptr\s*\[edi\]",
                r"mov\s*(e[a-z]{2}),\s*dword\s*ptr\s*\[esp\+(e[a-z]{2})\*1\]",
                r"sub\s*(ebp|esi),\s*0x4",
                r"mov\s*dword\s*ptr\s*\[(ebp|esi)\],\s*(e[a-z]{2})"
            ]
        ]
    
    def get_parameter(self, block: BasicBlock):
        for ins in block.instructions:
            match = re.search(r"mov\s*(e[a-z]{2}),\s*dword\s*ptr\s*\[esp\+(e[a-z]{2})\*1\]", ins.command)
            if match:
                register = match.group(2)
                param = ins.register[register]
                param = "vR" + str(int(int(param, 16) / 4))
                return param
        return ""


class Handler_vPopReg4(Handler):

    def __init__(self):
        super().__init__()
        self.name = "vPopReg4"
        self.signature_instructions = [
            [
                r"mov\s*(e[a-z]{2}),\s*dword\s*ptr\s*.*\[(ebp|esi)\]",
                r"add\s*(ebp|esi),\s*0x4",
                r"movzx\s*(e[a-z]{2}),\s*byte\s*ptr\s*\[edi\]",
                r'mov\s*dword\s*ptr\s*\[esp\+(e[a-z]{2})\*1\],\s*(e[a-z]{2})'
            ],
            [
                r"mov\s*(e[a-z]{2}),\s*dword\s*ptr\s*.*\[(ebp|esi)\]",
                r"lea\s*(ebp|esi),\s*ptr\s*\[(ebp|esi)\+0x4\]",
                r"movzx\s*(e[a-z]{2}),\s*byte\s*ptr\s*\[edi\]",
                r'mov\s*dword\s*ptr\s*\[esp\+(e[a-z]{2})\*1\],\s*(e[a-z]{2})'
            ]
        ]
    
    def get_parameter(self, block: BasicBlock):
        for ins in block.instructions:
            match = re.search(r"mov\s*dword\s*ptr\s*\[esp\+(e[a-z]{2})\*1\],\s*(e[a-z]{2})", ins.command)
            if match:
                register = match.group(1)
                param = ins.register[register]
                param = ins.register[register]
                param = "vR" + str(int(int(param, 16) / 4))
                return param
        return ""


class Handler_vAdd4(Handler):

    def __init__(self):
        super().__init__()
        self.name = "vAdd4"
        self.signature_instructions_has_order = True
        self.signature_instructions = [
            [
                r"mov\s*(e[a-z]{2}),\s*dword\s*ptr\s*\[(ebp|esi)\]",
                r"add\s*(e[a-z]{2}),\s*(e[a-z]{2})",
                r"pushfd",
                r"pop\s*dword\s*ptr\s*\[(ebp|esi)\]"
            ],
        ]

class Handler_vNand4(Handler):

    def __init__(self):
        super().__init__()
        self.name = "vNand4"
        self.signature_instructions = [
            [
                r"mov\s*(e[a-z]{2}),\s*dword\s*ptr\s*\[(ebp|esi)\]",
                r"mov\s*(e[a-z]{2}),\s*dword\s*ptr\s*\[(ebp|esi)\+0x4\]",
                r"not\s*(e[a-z]{2})",
                r"not\s*(e[a-z]{2})",
                r"pushfd",
                r"pop\s*dword\s*ptr\s*\[(ebp|esi)\]"
            ],
        ]

class Handler_vReadMemSs4(Handler):

    def __init__(self):
        super().__init__()
        self.name = "vReadMemSs4"
        self.signature_instructions = [
            [
                r"mov\s*(e[a-z]{2}),\s*dword\s*ptr\s*\[(ebp|esi)[^\]]*\]",
                r"mov\s*(e[a-z]{2}),\s*dword\s*ptr\s*ss:\[(e[a-z]{2})[^\]]*\]",
                r"mov\s*dword\s*ptr\s*\[(ebp|esi)\],\s*(e[a-z]{2})"
            ],
        ]

class Handler_vShr4(Handler):

    def __init__(self):
        super().__init__()
        self.name = "vShr4"
        self.signature_instructions_has_order = True
        self.signature_instructions = [
            [
                r"mov\s*(e[a-z]{2}),\s*dword\s*ptr\s*\[(ebp|esi)\]",
                r"mov\s*([a-z]{2}),\s*byte\s*ptr\s*\[(ebp|esi)\+0x4\]",
                r"sub\s*(ebp|esi),\s*0x2",
                r"shr\s*(e[a-z]{2}),\s*([a-z]{2})"
            ],
        ]

class Handler_vPushVEsp(Handler):

    def __init__(self):
        super().__init__()
        self.name = "vPushVEsp"
        self.signature_instructions_has_order = True
        self.signature_instructions = [
            r"mov\s*(e[a-z]{2}),\s*(ebp|esi)",
            r"sub\s*(ebp|esi),\s*0x4",
            r"lea\s*(ebp|esi),\s*ptr\s*\[(ebp|esi)\-0x4\]",
            r"mov\s*dword\s*ptr\s*\[(ebp|esi)\],\s*(e[a-z]{2})"
        ]

    def recognize(self, block: BasicBlock):
        if len(block.instructions) < 5:
            return False

        # 先把当前要判断的块的指令拼接在一起
        all_instructions = "\n".join(ins.command for ins in block.instructions)
        
        # 匹配四条特征指令，并提取命中的寄存器名
        match0 = re.search(self.signature_instructions[0], all_instructions)
        match1 = re.search(self.signature_instructions[1], all_instructions)
        match2 = re.search(self.signature_instructions[2], all_instructions)
        match3 = re.search(self.signature_instructions[3], all_instructions)
        if match0 and match3 and (match1 or match2):
            match0_reg1 = match0.group(1)
            match0_reg2 = match0.group(2)
            match3_reg1 = match3.group(1)
            match3_reg2 = match3.group(2)

            # 第一条特征指令和第四条特征指令的寄存器刚好反过来
            return match0_reg1 == match3_reg2 and match0_reg2 == match3_reg1
        
        return False

class Handler_vCheckVEsp(Handler):

    def __init__(self):
        super().__init__()
        self.name = "vCheckVEsp"
        self.bgcolor = "#D00C88"
        self.fontcolor = "white"
        self.signature_instructions_has_order = True
        self.signature_instructions = [
            [
                r"lea\s*(e[a-z]{2}),\s*ptr\s*\[esp\+0x60\]",
                r"cmp\s*(ebp|esi),\s*(e[a-z]{2})"
            ],
        ]

class Handler_vJmp(Handler):

    def __init__(self):
        super().__init__()
        self.name = "vJmp"
        self.bgcolor = "#FF0000"
        self.fontcolor = "white"
        self.signature_instructions_has_order = True
        self.signature_instructions = [
            [
                r"mov\s*(e[a-z]{2}),\s*dword\s*ptr\s*\[(esi|ebp)\]",
                r"add\s*(esi|ebp),\s*0x4",
                r"mov\s*edi,\s*(e[a-z]{2})"
            ],
        ]
    
    # def get_parameter(self, block: BasicBlock):
    #     for ins in block.instructions:
    #         match = re.search(r"mov\s*edi,\s*(e[a-z]{2})", ins.command)
    #         if match:
    #             register = match.group(1)
    #             param = "0x" + ins.register[register]
    #             return param
    #     return ""



class Handler_vEntryVM(Handler):

    def __init__(self):
        super().__init__()
        self.name = "vEntryVM"
        self.bgcolor = "#22A93D"
        self.fontcolor = "white"
        self.signature_instructions_has_order = False
        self.signature_instructions = [
            [
                r"push\s*ebx",
                r"push\s*ecx",
                r"push\s*ebp",
                r"push\s*edx",
                r"push\s*esi",
                r"push\s*eax",
                r"push\s*edi",
                r"pushfd"
            ],
        ]

class Handler_vRet(Handler):

    def __init__(self):
        super().__init__()
        self.name = "vRet"
        self.bgcolor = "#E45633"
        self.fontcolor = "white"
        self.signature_instructions_has_order = False
        self.signature_instructions = [
            [
                r"pop\s*ebx",
                r"pop\s*ecx",
                r"pop\s*ebp",
                r"pop\s*edx",
                r"pop\s*esi",
                r"pop\s*eax",
                r"pop\s*edi",
                r"popfd",
                r"ret"
            ],
        ]

class Handler_vLoadVEip(Handler):

    def __init__(self):
        super().__init__()
        self.name = "vLoadVEip"
        self.signature_instructions_has_order = False
        self.signature_instructions = [
            [
                r"lea\s*(ebp|esi),\s*ptr\s*\[0x.*\]",
                r"mov\s*(e[a-z]{2}),\s*dword\s*ptr\s*\[edi\]",
            ],
        ]

handler_list = [
    Handler_vEntryVM(),
    Handler_vPushReg4(),
    Handler_vPopReg4(),
    Handler_vNand4(),       # 必须放在vAdd4前面
    Handler_vAdd4(),
    Handler_vPushImm4(),    # 必须放在vPushReg4后面
    Handler_vPushImm2(),
    Handler_vReadMemSs4(),
    Handler_vCheckVEsp(),
    Handler_vShr4(),
    Handler_vJmp(),
    Handler_vPushVEsp(),
    Handler_vLoadVEip(),
    Handler_vRet()
]

def recognize_handler(block: BasicBlock):
    for handler in handler_list:
        if handler.recognize(block):
            return handler
    return None
    

# 构建虚拟指令流
def build_vmp_instructions(merged_blocks, full_blocks, output_file):

    # 先提取原来所有块所有出现的次序
    order_map = dict()
    for block in merged_blocks:
        # 识别每一个块
        handler = recognize_handler(block)
        if handler is not None:
            block.recognize_name = handler.get_name()
            block.block_bgcolor = handler.bgcolor
            block.block_fontcolor = handler.fontcolor

        for order in block.get_appearance_order():
            order_map[order] = {
                "block": block,
                "handler": handler
            }

    from collections import OrderedDict
    order_map = OrderedDict(sorted(order_map.items()))

    # 根据块的出场次序，定位到当初原始的块（去重之前真实执行流中的块），用于获取该代码块当次运行的参数信息
    origin_blocks_map = dict()
    order_list = list(order_map.keys())
    for i in range(len(order_list)):
        first_child_block_order = order_list[i]
        last_child_block_order = order_list[i+1]-1 if i < len(order_list)-1 else len(full_blocks)-1

        origin_block = BasicBlock(full_blocks[first_child_block_order].instructions)
        for n in range(first_child_block_order+1, last_child_block_order+1):
            origin_block.instructions.extend(full_blocks[n].instructions)
        
        origin_blocks_map[order_list[i]] = origin_block


    # 将代码块出现的顺序记录到文件中
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(f"--- VMP Instructions Flow ---\n")
        for order in order_map.keys():
            block = order_map[order]["block"]
            handler = order_map[order]["handler"]
            line = f"{block.block_name}\n"
            if handler is not None:
                if handler.get_name() == "vCheckVEsp":
                    continue
                else:
                    line = f"{block.block_name} {handler.get_name()} {handler.get_parameter(origin_blocks_map[order])} \n"

            f.write(line)


if __name__ == '__main__':
    target_file = "run_trace_crackme.vmp.3.5.0.txt"
    #target_file = "run_trace_antidebug.txt"
    #target_file = "run_trace.2.13.8.txt"
    target_dir = target_file + "_result"
    if not os.path.exists(target_dir):
        os.mkdir(target_dir)
    instructions = parse_trace_file(target_file)
    blocks = split_into_basic_blocks(instructions)
    blocks = build_control_flow_graph(blocks, True, None) # 第一次构建去重合并前的原始控制流转移关系

    # 构建原始指令流地址序列
    origin_instruction_order = []
    for e in instructions:
        origin_instruction_order.append(e.address)
    
    print(f"原始代码块数量: {len(blocks)}")
    save_blocks_txt(blocks, target_dir + "/rtrace_blocks_full.txt")
    
    # 去重处理
    unique_blocks, origin_index_to_unique_index, block_counts = deduplicate_blocks(blocks)
    print(f"去重后代码块数量: {len(unique_blocks)}")
    save_blocks_txt(unique_blocks, target_dir + "/rtrace_blocks_dedup.txt")

    # 合并串行块
    merged_blocks, merged_blocks_count = merge_serial_blocks(unique_blocks, block_counts)
    print(f"合并后代码块数量: {len(merged_blocks)}")
    save_blocks_txt(merged_blocks, target_dir + "/rtrace_blocks_merged.txt")
    
    # 重新为合并之后的块构建控制流转移关系
    build_control_flow_graph(merged_blocks, False, origin_instruction_order)

    # 构建VMP虚拟指令流
    build_vmp_instructions(merged_blocks=merged_blocks, full_blocks=blocks, output_file=target_dir + "/vmp_instructions.txt")
    print("生成VMP指令流完成")
    
    # 生成图表
    generate_dot_file(merged_blocks, merged_blocks_count, target_dir + "/rtrace_graphviz.dot")