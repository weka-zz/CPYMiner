import idautils
import idc
import json
import idaapi
import ida_ua
import ida_idp
import ida_ida
import re
import openai
import requests
import os
import time
from openai import OpenAI
from collections import deque

def get_basic_block_info(ea):
    func = ida_funcs.get_func(ea)
    if not func:
        print(f"No function found at {hex(ea)}")
        return None, 0

    flow_chart = idaapi.FlowChart(func)
    for block in flow_chart:
        if block.start_ea <= ea < block.end_ea:
            # 获取当前基本块的前驱基本块数
            predecessor_count = len(list(block.preds()))
           # print(f"Current Basic Block Start: {hex(block.start_ea)}")
            #print(f"Number of Predecessor Blocks: {predecessor_count}")
            return block.start_ea, predecessor_count

    print(f"No basic block found for {hex(ea)}")
    return None, 0


def parse_memory_operand_with_base(op):
    """
    解析 MIPS 内存操作数，包括偏移地址和基址寄存器。
    :param op: ida_ua.op_t 操作数对象
    :return: (地址字符串, 基地址寄存器)
    """
    if op.type == ida_ua.o_displ:
        reg_name = ida_idp.ph.regnames[op.reg]  # 基址寄存器
        offset = format_signed_immediate(op.addr, bits=16)  # 偏移量（符号化处理）
        return f"{offset}({reg_name})", reg_name
    elif op.type == ida_ua.o_mem:
        return hex(op.addr), None
    else:
        return "UNKNOWN", None


def format_signed_immediate(value, bits=16):
    """
    格式化立即数或偏移量为带符号的十六进制表示。
    :param value: 无符号整数
    :param bits: 立即数的位宽（默认为 16 位）
    :return: 带符号的十六进制字符串
    """
    sign_mask = 1 << (bits - 1)
    if value & sign_mask:
        value = value - (1 << bits)
    return f"{value:#x}"  # 返回带符号的十六进制字符串


def classify_mips_instruction(ea):
    """
    使用 IDAPython API 获取 MIPS 指令的操作码和操作数，并分类指令类型。
    :param ea: 指令地址
    :return: (instruction_type, destination, sources, base_registers)
    """
    imm = None
    instruction_type = "unknown"
    destination = None
    sources = []
    base_registers = []  # 用于记录内存操作数的基地址寄存器

    # 解析指令
    insn = ida_ua.insn_t()
    if not ida_ua.decode_insn(insn, ea):
        raise ValueError(f"Failed to decode instruction at address {hex(ea)}")

    # 获取操作码
    mnemonic = idc.print_insn_mnem(ea)
    #print(f"Decoded instruction at {hex(ea)}: {mnemonic}")

    # 定义指令类型分类
    instruction_map = {
        # "conditional_test": {"mnemonics": {"slt", "slti", "sltiu", "sltu","c.un.d","c.ule.d","c.eq.d","c.lt.s","c.lt.d","c.le.d","c.ult.d"}, "dest_index": 0, "source_indices": [1, 2]},
        "conditional_test": {"mnemonics": {"slt", "slti", "sltiu", "sltu"}, "dest_index": 0, "source_indices": [1, 2]},
        "branch_conditional_zero": {"mnemonics": {"bgtz","bgezal","bgez","beqz","beqzl","bnez","bc1t","bc1f"}, "dest_index": 1, "source_indices": [0]},
        "branch_conditional_lzero": {"mnemonics": {"blez","bltz","bltzal","bc1t","bc1f"}, "dest_index": 1, "source_indices": [0]},
        "branch_conditional": {"mnemonics": {"beq","bne", "tge", "tlt","bnel"},"dest_index": 2, "source_indices": [0,1]},
        "jump_register": {"mnemonics": {"jr"}, "dest_index": None, "source_indices": [0]},
        "jump_and_link": {"mnemonics": {"jal","bal"}, "dest_index": 0, "source_indices": []},
        "jump_and_link_register": {"mnemonics": {"jalr"}, "dest_index": 0, "source_indices": [1]},
        "jump": {"mnemonics": {"j","b"}, "dest_index": 0, "source_indices": []},
        "load": {"mnemonics": {"lw","lwl","lwr","ulw","ll","ldc1","lwc1"}, "dest_index": 0, "source_indices": [1]},
        "load_int": {"mnemonics": {"lb", "lbu", "lh", "lhu"},"dest_index": 0, "source_indices": [1]},
        "store": {"mnemonics": {"sw","swl","swr","usw","sc","sdc1","swc1"}, "dest_index": 1, "source_indices": [0]},
        "store_int": {"mnemonics": {"sb", "sh"}, "dest_index": 1,"source_indices": [0]},
        "arithmetic": {"mnemonics": {"add","addi", "addiu","addu"},"dest_index": 0, "source_indices": [1, 2]},
        "arithmetic_sub": {"mnemonics": {"sub", "subu" }, "dest_index": 0,"source_indices": [1, 2]},
        "float_arithmetic": { "mnemonics": {"add.s", "msub.d", "sub.d", "add.d", "madd.d","abs.d", "abs.s", "sqrt.s", "sqrt.d"}, "dest_index": 0, "source_indices": [1, 2, 3]},
        "arithmetic_with_imm": {"mnemonics": {"li", "lui"}, "dest_index": 0, "source_indices": [1]},
        "arithmetic_with_la":{"mnemonics": {"la"},"dest_index": 0, "source_indices": [1]},
        "arithmetic_move": {"mnemonics": {"clo","clz","move","negu", "seb","seh", "neg", "neg.d"}, "dest_index": 0, "source_indices": [1]},
        "mul_and_div": {"mnemonics": {"div", "divu", "madd", "maddu", "musub", "msubu", "mult", "multu", "mult.d", "mul.d", "mul.s","div.d", "div.s", }, "dest_index": None, "source_indices": [0, 1]},
        "mul": {"mnemonics": {"mul"}, "dest_index": 0, "source_indices": [1, 2]},
        "move": {"mnemonics": { "rdhwr", "wsbh"}, "dest_index": 0,"source_indices": [1]},
        "logic": {"mnemonics": {"and", "andi", "or","ori","xor", "xori", "nor","nori","not"},"dest_index": 0, "source_indices": [1, 2]},
        "shift_r": {"mnemonics": {"sll","sllv","sra", "srav","srl", "srlv"}, "dest_index": 0,"source_indices": [1, 2]},
        "bitoperate": {"mnemonics": {"rotr", "rotrv","rotl","wsbh","ext","ins"}, "dest_index": 0, "source_indices": [1, 2]},
        "irrelevant": {"mnemonics": {"sync","pref", "syscall","nop","break","nop","teqi"},"dest_index": 0, "source_indices": [1]},
        "float_move_arithmetic": {"mnemonics": {"cfc1", "neg.d", "trunc.w.d", "movt.d", "mov.d", "mov.s","mfhc1", "mfc1", "cvt.s.w", "cvt.w.d", "cvt.d.w"}, "dest_index": 0, "source_indices": [1, 2]},
        "move_float": {"mnemonics": {"ctc1", "mtc1", "mthc1", "mthi", "mtlo"}, "dest_index": 1, "source_indices": [0]},
        "accumulator":{"mnemonics":{"mfhi", "mflo"},"dest_index": 0,"source_indices": None},
        "conditional_move":{"mnemonics": {"movn","movz"}, "dest_index": 0, "source_indices": [1,2]}
    }

    # 确定指令类型
    for itype, data in instruction_map.items():
        if mnemonic in data["mnemonics"]:
            instruction_type = itype
            dest_index = data.get("dest_index")
            source_indices = data.get("source_indices", [])
            break
    else:
        print(f"Unrecognized mnemonic: {hex(ea)},{mnemonic}")
        return instruction_type, destination, sources, base_registers, imm

    # 解析操作数
    for i in range(6):  # MIPS 最多有 6 个操作数
        op = insn.ops[i]
        if op.type == ida_ua.o_void:
            break

        # 格式化操作数
        if op.type == ida_ua.o_reg:
            operand = ida_idp.ph.regnames[op.reg]
            #print(operand)
        elif op.type == ida_ua.o_imm:
            operand = hex(op.value)
            imm = op.value
        elif op.type in {ida_ua.o_mem, ida_ua.o_displ}:
            # 解析内存操作数，返回地址和基地址寄存器
            operand, base_reg = parse_memory_operand_with_base(op)
            if base_reg:
                base_registers.append(base_reg)  # 记录基地址寄存器
        elif op.type == ida_ua.o_near:
            operand = hex(op.addr)
        else:
            operand = "UNKNOWN"


        if i == dest_index:
            destination = operand
        if source_indices!=None and i in source_indices:
            sources.append(operand)

    #print(destination, sources, base_registers)
    return instruction_type, destination, sources, base_registers, imm


def collect_instruction_stream(func_addr, basic_blocks, longest_route, analyzed_blocks=None, block_start=None, instruction_stream=None):
    """
    非递归分析基本块并收集指令地址流。
    """
    if analyzed_blocks is None:
        analyzed_blocks = set()
    if instruction_stream is None:
        instruction_stream = []
    last_block=[]

    stack = [block_start]
    for block in basic_blocks:
        if block["successors"]==[] and longest_route and block in longest_route:
            last_block.append[block]
    for block in basic_blocks:
        if block["successors"]==[] and longest_route and block not in longest_route:
            last_block.append(block)

    while stack:
        block_start = stack.pop()
        print("===========", hex(block_start))
        block = next((b for b in basic_blocks if b["start_ea"] == block_start), None)

        if not block or block["start_ea"] in analyzed_blocks:
            continue

        analyzed_blocks.add(block["start_ea"])

        for insn_addr in block["instructions"]:
            instruction_stream.append(insn_addr)

        successors = list(sorted(block["successors"], reverse=True))

        # 优先入栈不在最长路径上的基本块
        non_longest_successors = [s for s in successors if s not in longest_route and s not in analyzed_blocks]
        longest_successors = [s for s in successors if s in longest_route and s not in analyzed_blocks and s != last_block]

        for succ_start in non_longest_successors:
            stack.append(succ_start)
            #print("******** 非最长路径块", hex(succ_start))

        if longest_successors:
            # 按最长路径上的索引降序排序
            sorted_successors = sorted(longest_successors, key=lambda x: longest_route.index(x), reverse=True)
            for succ_start in sorted_successors:
                stack.append(succ_start)
                #print("+++++++++ 最长路径块", hex(succ_start))

    # 确保最后一个基本块被处理
    for lblock in last_block:
        if lblock and lblock["start_ea"] not in analyzed_blocks:
            #print("=========== 最后一个基本块", hex(last_block))
            analyzed_blocks.add(lblock["start_ea"])
            block = next((b for b in basic_blocks if b["start_ea"] == lblock["start_ea"]), None)
            if block:
                for insn_addr in block["instructions"]:
                    instruction_stream.append(insn_addr)
    return instruction_stream
def get_function_basic_blocks(func_addr):
    """
    获取函数的基本块信息。
    :param func_addr: 函数起始地址
    :return: 包含基本块信息的列表
    """
    func = idaapi.get_func(func_addr)
    if not func:
        print(f"Invalid function address: {hex(func_addr)}")
        return []

    # 使用 FlowChart 获取基本块
    flowchart = idaapi.FlowChart(func)

    basic_blocks = []
    for block in flowchart:
        block_info = {
            "start_ea": block.start_ea,
            "end_ea": block.end_ea,
            "instructions": [],  # 添加存储指令的字段
            "successors": [succ.start_ea for succ in block.succs()],
            "predecessors": [pred.start_ea for pred in block.preds()],
        }

        # 获取基本块中的每条指令地址
        for ea in range(block.start_ea, block.end_ea):
            if idc.print_insn_mnem(ea):  # 如果地址包含有效指令
                block_info["instructions"].append(ea)

        basic_blocks.append(block_info)

    blocks = list(flowchart)  # 基本块列表
    max_len_list = [0 for block in blocks]  # 到达各基本块的最大距离，初始化为0
    longest_route_list = [[] if list(block.preds()) else [block.start_ea] for block in
                          blocks]  # 到达各基本块的最长路径，起始基本块初始化为自身，其余初始化为空
    inst_num_list = [0 for block in blocks]  # 到达各基本块最长路径包含的指令数（不包括自身），初始化为0
    block_idx = dict((block.start_ea, i) for i, block in enumerate(blocks))  # 字典：基本块起始地址→序号
    max_len_sum = 0  # 一轮遍历结束时，到达各基本块的最大距离之和
    loop_num = 1  # 遍历次数
    while loop_num < len(blocks):  # 对于不考虑循环的控制流图，遍历次数不应大于基本块数量
        loop_num += 1
        for block in blocks:  # 遍历各基本块
            idx = block_idx[block.start_ea]  # 该基本块序号
            longest_route = longest_route_list[idx]  # 到达该基本块的最长路径
            if not longest_route:  # 还没有一条从起始基本块到该基本块的路径
                continue
            max_len = max_len_list[idx]  # 到达该基本块的最大距离
            for succ_block in block.succs():  # 遍历该基本块后继
                if succ_block.start_ea in longest_route:  # 已出现在最长路径中，不再执行后续步骤，避免循环
                    continue
                succ_idx = block_idx[succ_block.start_ea]  # 该后继基本块序号
                if max_len + 1 > max_len_list[succ_idx]:  # 发现更长路径
                    max_len_list[succ_idx] = max_len + 1  # 更新到该后继基本块的最大距离、最长路径和指令数
                    longest_route_list[succ_idx] = longest_route + [succ_block.start_ea]
                    inst_num_list[succ_idx] = inst_num_list[idx] + len(basic_blocks[idx]["instructions"])
                elif max_len + 1 == max_len_list[succ_idx]:  # 发现等长路径，比较路径包含的指令数
                    if inst_num_list[idx] + len(basic_blocks[idx]["instructions"]) > inst_num_list[
                        succ_idx]:  # 新路径指令数更多
                        max_len_list[succ_idx] = max_len + 1  # 更新到该后继基本块的最大距离、最长路径和指令数
                        longest_route_list[succ_idx] = longest_route + [succ_block.start_ea]
                        inst_num_list[succ_idx] = inst_num_list[idx] + len(basic_blocks[idx]["instructions"])

        if sum(max_len_list) == max_len_sum:  # 最大距离之和如果没有更新，则没有更长的路径，结束遍历
            break
        max_len_sum = sum(max_len_list)

    max_len = max(max_len_list)  # 最大距离
    max_inst_num, longest_route = 0, None  # 最大指令数，最长路径
    for i in range(len(blocks)):
        if max_len_list[i] == max_len:
            if inst_num_list[i] + len(basic_blocks[i]["instructions"]) > max_inst_num:  # 指令数更多
                max_inst_num = inst_num_list[i] + len(basic_blocks[i]["instructions"])
                longest_route = longest_route_list[i]
    print(' '.join(map(hex, longest_route)))  # 把最长路径中的基本块转换成起始地址输出
    return basic_blocks,longest_route


def get_function_instructions(func_addr):
    """
    获取函数的所有指令地址。
    """
    func = idaapi.get_func(func_addr)
    if not func:
        print(f"Invalid function address: {hex(func_addr)}")
        return []

    basic_blocks,longest_route = get_function_basic_blocks(func_addr)
    print(longest_route)
    if basic_blocks:
        instructions = collect_instruction_stream(func_addr, basic_blocks, longest_route,block_start=basic_blocks[0]["start_ea"])

    return instructions



def signed_hex_to_decimal(hex_value, bits=32):
    """
    将有符号十六进制数转换为十进制。
    :param hex_value: 十六进制整数
    :param bits: 整数的位数（默认32位）
    :return: 十进制整数
    """
    # 检查符号位并转换为有符号整数
    if hex_value >= (1 << (bits - 1)):
        return hex_value - (1 << bits)
    else:
        return hex_value

def analyze_instruction(addr, param_status, param_types, mem_status, param_mem, stack_var):
    """
    分析单条指令，更新参数状态和类型。
    :param addr: 指令地址
    :param param_status: 当前参数状态字典
    :param param_types: 当前参数类型字典
    :return: 更新后的参数状态和类型
    """
    global all_func_param
    param_registers = ["$a0", "$a1", "$a2", "$a3"]

    disasm = idc.GetDisasm(addr)
    if not disasm:
        return param_status, param_types ,mem_status, param_mem, stack_var
    global fpflag
    # 分类指令
    instruction_type, destination, sources, base_registers, imm = classify_mips_instruction(addr)
    if instruction_type in {"arithmetic_move"}:
        if destination =="$fp" and sources[0] !="$sp":
            fpflag = 1
        if destination == "$fp" and sources[0] =="$sp":
            fpflag = 0
    if instruction_type in {"arithmetic"}:
        if destination=="$sp" and imm!=None:
            if signed_hex_to_decimal(imm, bits=32)<0:
                stack_var=-signed_hex_to_decimal(imm, bits=32)
                print(hex(addr),hex(stack_var))
    if instruction_type in {"store","store_int"}:
        if "$fp" in destination:
            mem_status[destination] = "True"
        if "$sp" in destination:
            mem_status[destination] = "True"
        #print(mem_status)
    if instruction_type in {"load","load_int"}:
        if sources[0] not in mem_status and "$fp" in sources[0] and sources[0] not in param_mem and "$gp" not in destination and fpflag==0:
            # print(hex(addr),sources[0])
            if extract_offset(sources[0]) >= stack_var and extract_offset(sources[0])<=0x220:
                param_mem.append(sources[0])
        if sources[0] not in mem_status and "$sp" in sources[0]  and sources[0] not in param_mem and "$gp" not in destination:
            if extract_offset(sources[0])>=stack_var and extract_offset(sources[0])<=0x220:
                param_mem.append(sources[0])
                print("++++****++++++", hex(extract_offset(sources[0])))

    # 忽略不相关指令
    if instruction_type in {"jump", "irrelevant", "jump_and_link"}:
        return param_status, param_types, mem_status, param_mem, stack_var



    # 检查目标寄存器是否为参数寄存器
    if destination in param_registers:
        reg_type = "unknown"
        if instruction_type in {"move", "load", "load_int","float_move_arithmetic","move_float","arithmetic_with_la","arithmetic_with_imm","conditional_move","accumulator","mul"}:
            param_status[destination] = True
            #print(hex(addr),destination,sources,param_types)
        if instruction_type in {"arithmetic_move"}:
           # print(hex(addr),destination,sources)
            if destination in sources and not param_status[destination]:
                param_types[destination] = "interger"
            param_status[destination] = True

        if len(sources)==2:
            if instruction_type in {"conditional_test","conditional_move"}:
                param_status[destination] = True
            if instruction_type in {"logic"}:
                if destination in sources and not param_status[destination]:
                    param_types[destination]="interger"
                    param_status[destination] = True
                else:
                    param_status[destination] = True
            if instruction_type in {"arithmetic","arithmetic_sub", "logic", "shift_r","bitoperate"}:
                if destination in sources and not param_status[destination]:
                    param_types[destination]="interger"
                    param_status[destination] = True
                else:
                    param_status[destination] = True
        if len(sources)==1:
            if instruction_type in {"arithmetic", "arithmetic_sub","shift_r","logic", "bitoperate","logic"}:
                if not param_status[destination]:
                    param_types[destination] = "interger"
                    param_status[destination] = True
                #param_status[destination] = True

    # 检查源寄存器是否为参数寄存器
    for src in sources:
        if src in param_registers and not param_status[src]:
            reg_type = "unknown"
            if instruction_type in {"store","store_int", "move", "arithmetic_move","mul_and_div","move_float","mul","float_arithmetic"}:
               # print(hex(addr),sources,destination)
                param_types[src] = "interger"
            elif instruction_type in {"conditional_test"}:
                param_types[src] = "interger"
            elif instruction_type in {"arithmetic","arithmetic_sub", "logic","shift_r", "bitoperate","logic"}:
                param_types[src] = "interger"
            elif instruction_type in {"branch_conditional","branch_conditional_zero","branch_conditional_lzero"}:
                param_types[src] = "interger"
            elif instruction_type in {"jump_register","jump_and_link_register"}:
                param_types[src] = "pointer"

            param_status[src] = True
    # 检查基址寄存器是否为参数寄存器
    for base_register in base_registers:
        if base_register in param_registers and not param_status[base_register]:
            if instruction_type in {"store","store_int", "load","load_int"} and not param_status[base_register]:
                param_types[base_register] = "pointer"
                #print(hex(addr),destination,sources,param_types)
                param_status[base_register] = True

    return param_status, param_types ,mem_status, param_mem, stack_var


def extract_offset(item):
    # 提取括号前的偏移地址并转换为整数
    return int(item.split('(')[0], 16)

def sort_by_offset(address_list):
    # 按偏移地址排序
    return sorted(address_list, key=extract_offset)

def update_param_status(param_types,param_mem):
    """
    按寄存器顺序返回有效参数。
    如果某个寄存器被标记为参数，则它之前的所有寄存器也视为参数，
    而之后的寄存器都不再是参数（如 $a3 不是参数）。

    :param param_types: 参数类型字典，存储已识别的寄存器及其类型。
                        键为寄存器名，值为参数类型。
    :return: (有效参数字典, 按寄存器顺序排列的有效参数列表)
    """
    param_registers = ["$a0", "$a1", "$a2", "$a3"]  # 参数寄存器顺序
    valid_params_dict = {}  # 存储有效参数的字典
    valid_params_list = []  # 存储有效参数的列表

    # 找到最后一个有效参数寄存器的索引
    last_valid_index = -1
    for i, reg in enumerate(param_registers):
        if reg in param_types:
            last_valid_index = i  # 更新最后一个有效参数的索引

    # 如果有有效参数，则处理最后一个有效寄存器之前的所有寄存器
    if last_valid_index >= 0:
        for i in range(last_valid_index + 1):
            reg = param_registers[i]
            if reg in param_types:
                # 如果寄存器已标记为参数，保留其类型
                valid_params_dict[reg] = param_types[reg]
            else:
                # 如果寄存器未被标记为参数，默认类型为 "unknown"
                valid_params_dict[reg] = "unknown"
            valid_params_list.append(reg)
    param_mem_sort = sort_by_offset(param_mem)

    return valid_params_dict, valid_params_list,param_mem_sort

# def update_param_status(param_types,param_mem):
#     """
#     按寄存器顺序返回有效参数。
#     如果某个寄存器被标记为参数，则它之前的所有寄存器也视为参数，
#     而之后的寄存器都不再是参数（如 $a3 不是参数）。
#
#     :param param_types: 参数类型字典，存储已识别的寄存器及其类型。
#                         键为寄存器名，值为参数类型。
#     :return: (有效参数字典, 按寄存器顺序排列的有效参数列表)
#     """
#     param_registers = ["$a0", "$a1", "$a2", "$a3"]  # 参数寄存器顺序
#     valid_params_dict = {}  # 存储有效参数的字典
#     valid_params_list = []  # 存储有效参数的列表
#     param_mem_sort=[]
#     if param_mem:
#         param_mem_sort = sort_by_offset(param_mem)
#         for reg in param_registers:
#             if reg in param_types:
#                 valid_params_dict[reg] = param_types[reg]
#             else:
#                 valid_params_dict[reg]="unknown"
#         return valid_params_dict,param_registers, param_mem_sort
#     # 找到最后一个有效参数寄存器的索引
#     else:
#         last_valid_index = -1
#         for i, reg in enumerate(param_registers):
#             if reg in param_types:
#                 last_valid_index = i  # 更新最后一个有效参数的索引
#
#         # 如果有有效参数，则处理最后一个有效寄存器之前的所有寄存器
#         if last_valid_index >= 0:
#             for i in range(last_valid_index + 1):
#                 reg = param_registers[i]
#                 if reg in param_types:
#                     # 如果寄存器已标记为参数，保留其类型
#                     valid_params_dict[reg] = param_types[reg]
#                 else:
#                     # 如果寄存器未被标记为参数，默认类型为 "unknown"
#                     valid_params_dict[reg] = "unknown"
#                 valid_params_list.append(reg)
#     return valid_params_dict,valid_params_list,param_mem_sort


# def update_param_status(param_types,param_mem):
#     """
#     按寄存器顺序返回有效参数。
#     如果某个寄存器被标记为参数，则它之前的所有寄存器也视为参数，
#     而之后的寄存器都不再是参数（如 $a3 不是参数）。
#
#     :param param_types: 参数类型字典，存储已识别的寄存器及其类型。
#                         键为寄存器名，值为参数类型。
#     :return: (有效参数字典, 按寄存器顺序排列的有效参数列表)
#     """
#     param_registers = ["$a0", "$a1", "$a2", "$a3"]  # 参数寄存器顺序
#     valid_params_dict = {}  # 存储有效参数的字典
#     valid_params_list = []  # 存储有效参数的列表
#     param_mem_sort=[]
#     last_valid_index = -1
#     for i, reg in enumerate(param_registers):
#         if reg in param_types:
#             last_valid_index = i  # 更新最后一个有效参数的索引
#
#     # 如果有有效参数，则处理最后一个有效寄存器之前的所有寄存器
#     if last_valid_index >= 0:
#         for i in range(last_valid_index + 1):
#             reg = param_registers[i]
#             if reg in param_types:
#                 # 如果寄存器已标记为参数，保留其类型
#                 valid_params_dict[reg] = param_types[reg]
#             else:
#                 # 如果寄存器未被标记为参数，默认类型为 "unknown"
#                 valid_params_dict[reg] = "unknown"
#             valid_params_list.append(reg)
#     if len(valid_params_list) == 4:
#         param_mem_sort = sort_by_offset(param_mem)
#     else:
#         param_mem_sort=[]
#
#     return valid_params_dict,valid_params_list,param_mem_sort


def analyze_function_parameters(func_addr):
    """
    分析函数的参数及其类型。
    :param func_addr: 函数起始地址
    :return: 参数类型字典和参数列表
    """
    param_registers = ["$a0", "$a1", "$a2", "$a3"]
    param_status = {reg: False for reg in param_registers}
    param_types = {}
    mem_status={}
    param_mem=[]
    stack_var=0
    func_name = idc.get_func_name(func_addr)

    # 获取函数的所有指令
    instructions = get_function_instructions(func_addr)

    # 分析每条指令
    for addr in instructions:
        param_status, param_types, mem_status, param_mem, stack_var= analyze_instruction(addr, param_status, param_types, mem_status, param_mem,stack_var)

    # 更新参数状态
    #param_mem

    param_types,params, param_mem = update_param_status(param_types,param_mem)
    #print(func_name,params, param_mem)

    return param_types, params, param_mem,stack_var
def extract_function_name(instr):
    """
    从字符串中提取目标函数名。
    :param instr: 汇编指令字符串，例如 "jr $t9  # sub_41B070"
    :return: 提取的函数名或 None
    """
    # 定义正则表达式匹配目标函数
    match = re.search(r"; \s*([\w_]+)", instr)
    if match:
        return match.group(1)  # 返回匹配的目标函数名
    else:
        match = re.search(r"#\s*([\w_]+)", instr)
        if match:
            return match.group(1)
    return None

def track_parameter_flow(func_addr, parameters,param_types,param_mem,stack_var):#数据跟踪的过程中需要考虑延时槽的问题
    """
    分别跟踪每个参数的数据流传播过程，包括寄存器与内存交互。
    :param func_addr: 函数地址
    :param parameters: 初始参数列表 (寄存器或内存地址，如 ['$a0', '$a1'] 或栈地址)
    :return: 每个参数的传播路径的完整信息
    """
    func = idaapi.get_func(func_addr)
    if not func:
        raise ValueError(f"Invalid function address: {hex(func_addr)}")
    funname=idc.get_func_name(func_addr)

    reg_value={}
    all_flows = {}  # 存储所有参数的传播路径
    params={}
    if len(parameters)==4:
        nparameters=parameters+param_mem
    else:
        nparameters = parameters
    print( funname,parameters,param_mem)
    print("type:", param_types)
    start_address = ida_ida.inf_get_min_ea()
    end_address = ida_ida.inf_get_max_ea()

    instructions = get_function_instructions(func_addr)
    #basic_blocks = get_function_basic_blocks(func_addr)

    # 初始化每个参数的独立追踪

    args= []
    argslist = {}
    flags = 0
    cflags = 0
    eflags = 0
    cflag =0
    regtype ={}
    insts={}
    flow_info={}
    for para in params:
        regtype[para] = params[para]
    memory_map_type ={}
    memory_map = {}  # 内存地址到参数相关寄存器的映射
    reg_map={}
    inte_reg={}
    sub_inte_reg={}
    for param in parameters:
        reg_map[param]=param  # 参数寄存器 -> 来源映射
        flow_info[param]=[]
    if len(parameters) == 4:
        for param in param_mem:
            # 获取 param 在 param_mem 中的下标
            param_index = param_mem.index(param)
            reg="a"+str(param_index+4)
            param_types[reg]="unknown"
            memory_map[param]=reg
            reg_map[reg]=reg
            flow_info[reg]=[]
    print(f"开始追踪参数的数据流...\n")
    i = 0
    m=4

    while i < len(instructions):  # Continue until we reach the end of instructions
        addr = instructions[i]  # 不包括最后一条指令
        mnemonic, destination, sources, base_registers, imm = classify_mips_instruction(addr)
        if mnemonic in {"jump_and_link","jump_register","jump_and_link_register","jump","branch_conditional"}:
             if cflags==0:
                 cflags=1
                 i=i+1
                 continue
             if cflags==1:
                 eflags=1

        if cflags == 1 and eflags==0:
            i=i-1
        elif cflags == 1 and eflags==1:
            i=i+2
            eflags=0
            cflags=0
        elif cflags==0 and eflags==0:
            i=i+1

        if mnemonic in {"irrelevant"}:
            continue
        if mnemonic in {"accumulator"}:
            if destination in reg_map:
                print(f"+++++++++Decoded instruction at {hex(addr)}: {mnemonic}")
                flow_info[reg_map[destination]].append({
                    "address": hex(addr),
                    "mnemonic": mnemonic,
                    "type": "addr_to_reg",
                    "destination":destination,
                    "sources": [sources]
                })
                regtype[destination] = "interger"
                reg_map.pop(destination)
            else:
                regtype[destination] = "interger"

        if mnemonic in {"jump_and_link_register","jump_register"} and sources[0] in reg_map:
            src_reg=sources[0]
            print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
            if src_reg in reg_map:
                param_types[reg_map[src_reg]] = "pointer"
                params[reg_map[src_reg]]="pointer"
                regtype[src_reg]="pointer"
                regtype[reg_map[src_reg]]="pointer"
                #print("参数是函数的调用地址")
                print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                reg_var = reg_map[src_reg]
                for mem in list(memory_map):
                    if memory_map[mem] == reg_map[src_reg]:
                        memory_map_type[mem] = regtype[src_reg]
                        memory_map.pop(mem)
                for reg in list(reg_map):
                    if reg_map[reg]==reg_var:
                        regtype[reg]=regtype[reg_var]
                        reg_map.pop(reg)
                if reg_map=={} and memory_map=={}:
                    break
        if mnemonic in {"mul_and_div"}:
            mflag=0
            print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
            for src_reg in sources:
                regtype[src_reg]="interger"
                if src_reg in reg_map:
                    param_types[reg_map[src_reg]]="interger"
                    params[reg_map[src_reg]]="interger"
                    regtype[reg_map[src_reg]]="interger"
                    mflag=1
                    print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                    reg_var = reg_map[src_reg]
                    for mem in list(memory_map):
                        if memory_map[mem] == reg_map[src_reg]:
                            memory_map_type[mem] = regtype[src_reg]
                            memory_map.pop(mem)
                    for reg in list(reg_map):
                        if reg_map[reg]==reg_var:
                            regtype[reg]=regtype[reg_var]
                            reg_map.pop(reg)
            if mflag==1:
                if reg_map=={} and memory_map=={}:
                    break
        if mnemonic in {"mul"}:
            mflag=0
            print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
            regtype[destination] = "interger"
            for src_reg in sources:
                regtype[src_reg]="interger"
                if src_reg in reg_map:
                    param_types[reg_map[src_reg]]="interger"
                    params[reg_map[src_reg]]="interger"
                    regtype[reg_map[src_reg]]="interger"
                    mflag=1
                    print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                    reg_var = reg_map[src_reg]
                    for mem in list(memory_map):
                        if memory_map[mem] == reg_map[src_reg]:
                            memory_map_type[mem] = regtype[src_reg]
                            memory_map.pop(mem)
                    for reg in list(reg_map):
                        if reg_map[reg]==reg_var:
                            regtype[reg]=regtype[reg_var]
                            reg_map.pop(reg)
            if mflag==1:
                if reg_map=={} and memory_map=={}:
                    break
            if destination in reg_map:
                reg_map.pop(destination)

        if mnemonic in {"store"} :
            mem_addr = destination
            if sources[0] not in {"$gp","$ra","$fp"} and "$sp" in mem_addr:
                if stack_var>0 and extract_offset(destination) < stack_var:
                    args.append(mem_addr)
                if stack_var==0:
                    args.append(mem_addr)

            if len(base_registers)>0:#sw      $v0, __libc_multiple_libcs
                base_register=base_registers[0]
                src_reg = sources[0]
                #print(hex(addr), sources[0], mem_addr)
                if base_register in reg_map:
                    print(reg_map,regtype)
                    print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                    flow_info[reg_map[base_register]].append({
                        "address": hex(addr),
                        "mnemonic": mnemonic,
                        "type": "mem_to_reg",
                        "destination": mem_addr,
                        "sources": sources
                    })
                    #print("参数被用作基地址")
                    param_types[reg_map[base_register]] = "pointer"
                    params[reg_map[base_register]] = "pointer"
                    regtype[reg_map[base_register]] = "pointer"
                    regtype[base_register] = "pointer"
                    print(reg_map,regtype)
                    print(f"[INFO] 参数 {reg_map[base_register]} 的传播链: {flow_info[reg_map[base_register]]}\n")
                    reg_var = reg_map[base_register]
                    # print(reg_var)
                    if reg_var in inte_reg:
                        print(inte_reg[reg_var])
                        regtype[inte_reg[reg_var]] = "interger"
                        param_types[inte_reg[reg_var]] = "interger"
                        params[inte_reg[reg_var]] = "interger"
                        print(f"[INFO] 参数 {inte_reg[reg_var]} 的传播链: {flow_info[inte_reg[reg_var]]}\n")
                        reg_var2 = inte_reg[reg_var]
                        for mem in list(memory_map):
                            if memory_map[mem] == reg_var2:
                                memory_map_type[mem] = regtype[reg_var2]
                                memory_map.pop(mem)
                        for reg in list(reg_map):
                            if reg_map[reg] == reg_var2:
                                reg_map.pop(reg)
                    if 'd'+reg_var in sub_inte_reg:
                        print(sub_inte_reg['d'+reg_var])
                        regtype[sub_inte_reg['d'+reg_var]] = "pointer"
                        param_types[sub_inte_reg['d'+reg_var]] = "pointer"
                        params[sub_inte_reg['d'+reg_var]] = "pointer"
                        print(f"[INFO] 参数 {sub_inte_reg['d'+reg_var]} 的传播链: {flow_info[sub_inte_reg['d'+reg_var]]}\n")
                        reg_var2=sub_inte_reg['d'+reg_var]
                        for mem in list(memory_map):
                            if memory_map[mem] == reg_var2:
                                memory_map_type[mem] = regtype[reg_var2]
                                memory_map.pop(mem)
                        for reg in list(reg_map):
                            if reg_map[reg] == reg_var2:
                                reg_map.pop(reg)
                    for mem in list(memory_map):
                        if memory_map[mem]==reg_map[base_register]:
                            memory_map_type[mem] = regtype[base_register]
                            memory_map.pop(mem)
                    for reg in list(reg_map):
                        if reg_map[reg]==reg_var:
                            regtype[reg]=regtype[reg_var]
                            reg_map.pop(reg)
                    if reg_map == {} and memory_map == {}:
                        break
                if base_register not in reg_map:
                    if src_reg not in reg_map and mem_addr not in memory_map:
                        if sources[0]=="$zero":
                            regtype[sources[0]] = "interger"
                            memory_map_type[mem_addr]=regtype[sources[0]]
                            print(hex(addr), sources[0], mem_addr, mnemonic)
                        if sources[0] in regtype:
                            memory_map_type[mem_addr] = regtype[sources[0]]
                            print(hex(addr), sources[0], mem_addr, mnemonic)
                    if src_reg in reg_map and mem_addr in memory_map:  # 仅追踪来源于当前参数的寄存器
                        print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                        print(reg_map,regtype)
                        memory_map[mem_addr] = reg_map[src_reg]
                        print(memory_map)
                        print(f"[DEBUG] 记录内存映射: {mem_addr} <- {reg_map[src_reg]}\n")
                        flow_info[reg_map[src_reg]].append({
                            "address": hex(addr),
                            "mnemonic": mnemonic,
                            "type": "reg_to_mem",
                            "destination": mem_addr,
                            "sources": [src_reg]
                        })
                        if src_reg in regtype:
                            memory_map_type[mem_addr] = regtype[src_reg]
                        if src_reg not in regtype and mem_addr in memory_map_type:
                            memory_map_type.pop(mem_addr)
                        print(reg_map,regtype)
                    if src_reg in reg_map and mem_addr not in memory_map:  # 仅追踪来源于当前参数的寄存器
                        print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                        print(reg_map,regtype,memory_map)
                        memory_map[mem_addr] = reg_map[src_reg]
                        print("++++******++++",memory_map)
                        print(f"[DEBUG] 记录内存映射: {mem_addr} <- {reg_map[src_reg]}\n")
                        flow_info[reg_map[src_reg]].append({
                            "address": hex(addr),
                            "mnemonic": mnemonic,
                            "type": "reg_to_mem",
                            "destination": mem_addr,
                            "sources": src_reg
                        })
                        if src_reg in regtype:
                            memory_map_type[mem_addr] = regtype[src_reg]
                        if src_reg not in regtype and mem_addr in memory_map_type:
                            memory_map_type.pop(mem_addr)
                        print(reg_map,regtype,memory_map)

                    if src_reg not in reg_map and mem_addr in memory_map:  # 仅追踪来源于当前参数的寄存器,例如sp
                        print(f"+++++++++Decoded instruction at {hex(addr)}: {mnemonic}")
                        print(f"[DEBUG] 记录内存映射: {mem_addr} <- {src_reg}\n")
                        print(reg_map,regtype)
                        flow_info[memory_map[mem_addr]].append({
                            "address": hex(addr),
                            "mnemonic": mnemonic,
                            "type": "reg_to_mem",
                            "destination": mem_addr,
                            "sources": [src_reg]
                        })
                        if src_reg in regtype:
                            memory_map_type[mem_addr] = regtype[src_reg]
                        if src_reg=="$zero":
                            memory_map_type[mem_addr] = "interger"
                        if src_reg not in regtype and mem_addr in memory_map_type:
                            memory_map_type.pop(mem_addr)
                        memory_map.pop(mem_addr)
                        print(reg_map,regtype)

        if mnemonic in {"store_int"}:
            rflags=0
            mem_addr = destination
            if sources[0] not in {"$gp","$ra","$fp"} and "$sp" in mem_addr:
                if stack_var>0 and extract_offset(destination) < stack_var:
                    args.append(mem_addr)
                if stack_var==0:
                    args.append(mem_addr)
                # if extract_offset(destination) < stack_var:
                #     args.append(mem_addr)
            if len(base_registers) > 0:  # sw      $v0, __libc_multiple_libcs
                base_register = base_registers[0]
                src_reg = sources[0]
                print(hex(addr), sources[0], mem_addr)
                if base_register in reg_map:
                    rflags=1
                    src_reg=sources[0]
                    print(f"***+++***Decoded instruction at {hex(addr)}: {mnemonic}")
                    print(reg_map, regtype)
                    flow_info[reg_map[base_register]].append({
                        "address": hex(addr),
                        "mnemonic": mnemonic,
                        "type": "mem_to_reg",
                        "destination": mem_addr,
                        "sources": sources
                    })
                    print(reg_map,regtype)
                    regtype[base_register] = "pointer"
                    regtype[reg_map[base_register]]="pointer"
                    param_types[reg_map[base_register]] ="pointer"
                    params[reg_map[base_register]] ="pointer"
                    print(f"[INFO] 参数 {reg_map[base_register]} 的传播链: {flow_info[reg_map[base_register]]}\n")
                    reg_var = reg_map[base_register]
                    regtype[src_reg]="interger"
                    # print(reg_var)
                    if reg_var in inte_reg:
                        print(inte_reg[reg_var])
                        regtype[inte_reg[reg_var]] = "interger"
                        param_types[inte_reg[reg_var]] = "interger"
                        params[inte_reg[reg_var]] = "interger"
                        print(f"[INFO] 参数 {inte_reg[reg_var]} 的传播链: {flow_info[inte_reg[reg_var]]}\n")
                        reg_var2 = inte_reg[reg_var]
                        for mem in list(memory_map):
                            if memory_map[mem] == reg_var2:
                                memory_map_type[mem] = regtype[reg_var2]
                                memory_map.pop(mem)
                        for reg in list(reg_map):
                            if reg_map[reg] == reg_var2:
                                reg_map.pop(reg)
                    if 'd'+reg_var in sub_inte_reg:
                        print(sub_inte_reg['d'+reg_var])
                        regtype[sub_inte_reg['d'+reg_var]] = "pointer"
                        param_types[sub_inte_reg['d'+reg_var]] = "pointer"
                        params[sub_inte_reg['d'+reg_var]] = "pointer"
                        print(f"[INFO] 参数 {sub_inte_reg['d'+reg_var]} 的传播链: {flow_info[sub_inte_reg['d'+reg_var]]}\n")
                        reg_var2=sub_inte_reg['d'+reg_var]
                        for mem in list(memory_map):
                            if memory_map[mem] == reg_var2:
                                memory_map_type[mem] = regtype[reg_var2]
                                memory_map.pop(mem)
                        for reg in list(reg_map):
                            if reg_map[reg] == reg_var2:
                                reg_map.pop(reg)
                    if sources[0] in reg_map:
                        regtype[reg_map[src_reg]]="interger"
                        param_types[reg_map[src_reg]] ="interger"
                        params[reg_map[src_reg]] ="interger"
                        print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                        reg_var2 = reg_map[src_reg]
                        for mem in list(memory_map):
                            if memory_map[mem] == reg_map[src_reg]:
                                memory_map_type[mem] = regtype[src_reg]
                                memory_map.pop(mem)
                        for reg in list(reg_map):
                            if reg_map[reg]==reg_var2:
                                regtype[reg]=regtype[reg_var2]
                                reg_map.pop(reg)
                    for mem in list(memory_map):
                        if memory_map[mem] == reg_var:
                            memory_map_type[mem] = regtype[base_register]
                            memory_map.pop(mem)
                    for reg in list(reg_map):
                        if reg_map[reg]==reg_var:
                            regtype[reg]=regtype[base_register]
                            reg_map.pop(reg)
                    if reg_map == {} and memory_map == {}:
                        break
                if base_register not in reg_map and rflags==0:
                    src_reg=sources[0]
                    if src_reg not in reg_map and mem_addr not in memory_map:
                        print(reg_map,regtype)
                        regtype[src_reg] = "interger"
                        memory_map_type[mem_addr] = regtype[src_reg]
                        print(reg_map,regtype)
                    if src_reg in reg_map and mem_addr in memory_map:  # 仅追踪来源于当前参数的寄存器
                        print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                        print(reg_map,regtype)
                        memory_map[mem_addr] = reg_map[src_reg]
                        print(f"[DEBUG] 记录内存映射: {mem_addr} <- {reg_map[src_reg]}\n")
                        flow_info[reg_map[src_reg]].append({
                            "address": hex(addr),
                            "mnemonic": mnemonic,
                            "type": "reg_to_mem",
                            "destination": mem_addr,
                            "sources": [src_reg]
                        })
                        regtype[src_reg] = "interger"
                        regtype[reg_map[src_reg]] = "interger"
                        memory_map_type[mem_addr] = "interger"
                        param_types[memory_map[mem_addr]]="interger"
                        params[memory_map[mem_addr]]="interger"
                        print(reg_map,regtype)
                        print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                        reg_var = reg_map[src_reg]
                        for mem in list(memory_map):
                            if memory_map[mem] == reg_map[src_reg]:
                                memory_map_type[mem] = regtype[src_reg]
                                memory_map.pop(mem)
                        for reg in list(reg_map):
                            if reg_map[reg]==reg_var:
                                regtype[reg]=regtype[reg_var]
                                reg_map.pop(reg)
                        if reg_map == {} and memory_map == {}:
                            break
                    if src_reg in reg_map and mem_addr not in memory_map:  # 仅追踪来源于当前参数的寄存器
                        print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                        print("regtype:",regtype)
                        memory_map[mem_addr] = reg_map[src_reg]
                        print(f"[DEBUG] 记录内存映射: {mem_addr} <- {reg_map[src_reg]}\n")
                        flow_info[reg_map[src_reg]].append({
                            "address": hex(addr),
                            "mnemonic": mnemonic,
                            "type": "reg_to_mem",
                            "destination": mem_addr,
                            "sources": [src_reg]
                        })
                        param_types[reg_map[src_reg]]="interger"
                        params[reg_map[src_reg]]="interger"
                        regtype[src_reg] = "interger"
                        regtype[reg_map[src_reg]]="interger"
                        memory_map_type[mem_addr] = "interger"
                        print(reg_map,regtype,memory_map)
                        print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                        reg_var = reg_map[src_reg]
                        for mem in list(memory_map):
                            if memory_map[mem] == reg_map[src_reg]:
                                memory_map_type[mem] = regtype[src_reg]
                                memory_map.pop(mem)
                        for reg in list(reg_map):
                            if reg_map[reg]==reg_var:
                                regtype[reg]=regtype[reg_var]
                                reg_map.pop(reg)
                        if reg_map == {} and memory_map == {}:
                            break
                    if src_reg not in reg_map and mem_addr in memory_map:  # 仅追踪来源于当前参数的寄存器,例如sp
                        print(f"+++++++++Decoded instruction at {hex(addr)}: {mnemonic}")
                        print(f"[DEBUG] 记录内存映射: {mem_addr} <- {src_reg}\n")
                        print(reg_map,regtype)
                        # if len(base_registers)>0 and base_registers[0] in reg_map:
                        flow_info[memory_map[mem_addr]].append({
                            "address": hex(addr),
                            "mnemonic": mnemonic,
                            "type": "reg_to_mem",
                            "destination": mem_addr,
                            "sources": [src_reg]
                        })
                        regtype[src_reg] = "interger"
                        memory_map_type[mem_addr] = regtype[src_reg]
                        memory_map.pop(mem_addr)
                        print(reg_map,regtype)

        # 内存到寄存器传播 (lw 指令)
        if mnemonic in {"conditional_test"}:  # slti,sltiu
            if len(sources) == 1:
                if imm != None:
                    imm = signed_hex_to_decimal(imm)
                    if imm !=0:
                        regtype[destination] = "interger"
                        if destination in reg_map:  # 源操作数是立即数
                            # print("================**3**=====================")
                            print(f"[DEBUG] 寄存器映射: {destination} <-{sources}\n")
                            print(regtype)
                            flow_info[reg_map[destination]].append({
                                "address": hex(addr),
                                "mnemonic": mnemonic,
                                "type": "conditional_test",
                                "destination": destination,
                                "sources": hex(imm)
                            })
                            param_types[reg_map[destination]] = "interger"
                            params[reg_map[destination]] = "interger"
                            regtype[reg_map[destination]] = "interger"
                            print(f"[INFO] 参数 {reg_map[destination]} 的传播链: {flow_info[reg_map[destination]]}\n")
                            reg_var = reg_map[destination]
                            for mem in list(memory_map):
                                if memory_map[mem] == reg_map[destination]:
                                    memory_map_type[mem] = regtype[destination]
                                    memory_map.pop(mem)
                            for reg in list(reg_map):
                                if reg_map[reg] == reg_var:
                                    regtype[reg] = regtype[reg_var]
                                    reg_map.pop(reg)
                            if reg_map == {} and memory_map == {}:
                                break
                if imm == None:  # destination 是被覆盖掉的，所以应该直接判断sources[0]就可以了
                    if sources[0] in reg_map:  # 源操作数是寄存器
                        src_reg = sources[0]
                        flow_info[reg_map[src_reg]].append({
                            "address": hex(addr),
                            "mnemonic": mnemonic,
                            "type": "conditional_test",
                            "destination": destination,
                            "sources": src_reg
                        })

                        if destination in regtype:
                            param_types[reg_map[src_reg]] = regtype[destination]
                            params[reg_map[src_reg]] = regtype[destination]
                            regtype[sources[0]] = regtype[destination]
                            regtype[reg_map[src_reg]] = regtype[destination]
                            regtype[destination] = "interger"
                            print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                            reg_var = reg_map[src_reg]
                            for mem in list(memory_map):
                                if memory_map[mem] == reg_map[src_reg]:
                                    memory_map_type[mem] = regtype[src_reg]
                                    memory_map.pop(mem)
                            for reg in list(reg_map):
                                if reg_map[reg] == reg_var:
                                    regtype[reg] = regtype[reg_var]
                                    reg_map.pop(reg)
                            if destination in reg_map:
                                reg_map.pop(destination)
                            if reg_map == {} and memory_map == {}:
                                break

                    if sources[0] not in reg_map:
                        if destination in regtype:
                            regtype[sources[0]] = regtype[destination]
                            print(reg_map, regtype)
                        regtype[destination] = "interger"
                        if destination in reg_map:
                            reg_map.pop(destination)

            if len(sources) == 2:
                if imm != None:
                    imm = signed_hex_to_decimal(imm)
                    if imm != 0:
                        src_reg = sources[0]
                        if src_reg in reg_map:
                            print(reg_map, regtype)
                            print(f"+++++++++Decoded instruction at {hex(addr)}: {mnemonic}")
                            print(f"[DEBUG] 寄存器映射: {destination} --{src_reg}\n")
                            flow_info[reg_map[src_reg]].append({
                                "address": hex(addr),
                                "mnemonic": mnemonic,
                                "type": "conditional_test",
                                "destination": destination,
                                "sources": [sources]
                            })
                            param_types[reg_map[src_reg]] = "interger"
                            params[reg_map[src_reg]] = "interger"
                            regtype[src_reg] = "interger"
                            regtype[reg_map[src_reg]] = "interger"
                            regtype[destination] = "interger"
                            if destination in reg_map:
                                reg_map.pop(destination)
                            print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                            reg_var = reg_map[src_reg]
                            for mem in list(memory_map):
                                if memory_map[mem] == reg_map[src_reg]:
                                    memory_map_type[mem] = regtype[src_reg]
                                    memory_map.pop(mem)
                            for reg in list(reg_map):
                                if reg_map[reg] == reg_var:
                                    regtype[reg] = regtype[reg_var]
                                    reg_map.pop(reg)
                            print("***", reg_map, regtype)
                            if reg_map == {} and memory_map == {}:
                                break

                        if src_reg not in reg_map:
                            if destination in reg_map:
                                print(f"+++++++++Decoded instruction at {hex(addr)}: {mnemonic}")
                                print(f"[DEBUG] 寄存器映射: {destination} --{src_reg}\n")
                                flow_info[reg_map[destination]].append({
                                    "address": hex(addr),
                                    "mnemonic": mnemonic,
                                    "type": "conditional_test",
                                    "destination": destination,
                                    "sources": sources
                                })
                                reg_map.pop(destination)
                            regtype[src_reg] = "interger"
                            regtype[destination] = "interger"
                if imm == None:
                    if sources[0] not in reg_map and sources[1] not in reg_map:
                        if sources[0] in regtype:
                            regtype[sources[1]] = regtype[sources[0]]
                            regtype[destination] = "interger"
                        if sources[1] in regtype:
                            regtype[sources[0]] = regtype[sources[1]]
                            regtype[destination] = "interger"
                        if sources[0] not in regtype and sources[1] not in regtype:
                            regtype[destination] = "interger"
                        if destination in reg_map:
                            reg_map.pop(destination)
                    if sources[0] in reg_map and sources[1] not in reg_map:
                        src_reg = sources[0]
                        if sources[1] in regtype:
                            regtype[src_reg] = regtype[sources[1]]
                            regtype[reg_map[src_reg]] = regtype[src_reg]
                            regtype[destination] = "interger"
                            param_types[reg_map[src_reg]] = regtype[src_reg]
                            params[reg_map[src_reg]] = regtype[src_reg]
                            print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                            reg_var = reg_map[src_reg]
                            for mem in list(memory_map):
                                if memory_map[mem] == reg_map[src_reg]:
                                    memory_map_type[mem] = regtype[src_reg]
                                    memory_map.pop(mem)
                            for reg in list(reg_map):
                                if reg_map[reg] == reg_var:
                                    regtype[reg] = regtype[reg_var]
                                    reg_map.pop(reg)
                            if destination in reg_map:
                                reg_map.pop(destination)
                            if reg_map == {} and memory_map == {}:
                                break
                        if sources[1] not in regtype:
                            regtype[destination] = "interger"
                            if destination in reg_map:
                                reg_map.pop(destination)

                    if sources[0] not in reg_map and sources[1] in reg_map:
                        src_reg = sources[0]
                        if sources[0] in regtype:
                            regtype[sources[1]] = regtype[src_reg]
                            regtype[reg_map[sources[1]]] = regtype[sources[1]]
                            regtype[destination] = "interger"
                            param_types[reg_map[sources[1]]] = regtype[sources[1]]
                            params[reg_map[sources[1]]] = regtype[sources[1]]
                            print(f"[INFO] 参数 {reg_map[sources[1]]} 的传播链: {flow_info[reg_map[sources[1]]]}\n")
                            reg_var = reg_map[sources[1]]
                            for mem in list(memory_map):
                                if memory_map[mem] == reg_map[sources[1]]:
                                    memory_map_type[mem] = regtype[sources[1]]
                                    memory_map.pop(mem)
                            for reg in list(reg_map):
                                if reg_map[reg] == reg_var:
                                    regtype[reg] = regtype[reg_var]
                                    reg_map.pop(reg)
                            if destination in reg_map:
                                reg_map.pop(destination)
                            if reg_map == {} and memory_map == {}:
                                break
                        if sources[0] not in regtype:
                            regtype[destination] = "interger"
                            if destination in reg_map:
                                reg_map.pop(destination)
                    if sources[0] in reg_map and sources[1] in reg_map:
                        src_reg = sources[0]
                        if sources[0] not in regtype and sources[1] in regtype:
                            regtype[src_reg] = regtype[sources[1]]
                            regtype[reg_map[src_reg]] = regtype[src_reg]
                            regtype[destination] = "interger"
                            param_types[reg_map[sources[0]]] = regtype[sources[0]]
                            params[reg_map[sources[0]]] = regtype[sources[0]]
                            print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                            reg_var = reg_map[src_reg]
                            for mem in list(memory_map):
                                if memory_map[mem] == reg_map[src_reg]:
                                    memory_map_type[mem] = regtype[src_reg]
                                    memory_map.pop(mem)
                            for reg in list(reg_map):
                                if reg_map[reg] == reg_var:
                                    regtype[reg] = regtype[reg_var]
                                    reg_map.pop(reg)
                            if destination in reg_map:
                                reg_map.pop(destination)
                            if reg_map == {} and memory_map == {}:
                                break
                        if sources[0] in regtype and sources[1] not in regtype:
                            regtype[sources[1]] = regtype[src_reg]
                            regtype[reg_map[sources[1]]] = regtype[sources[1]]
                            regtype[destination] = "interger"
                            param_types[reg_map[sources[1]]] = regtype[sources[1]]
                            params[reg_map[sources[1]]] = regtype[sources[1]]
                            print(f"[INFO] 参数 {reg_map[sources[1]]} 的传播链: {flow_info[reg_map[sources[1]]]}\n")
                            reg_var = reg_map[sources[1]]
                            for mem in list(memory_map):
                                if memory_map[mem] == reg_map[sources[1]]:
                                    memory_map_type[mem] = regtype[sources[1]]
                                    memory_map.pop(mem)
                            for reg in list(reg_map):
                                if reg_map[reg] == reg_var:
                                    regtype[reg] = regtype[reg_var]
                                    reg_map.pop(reg)
                            if destination in reg_map:
                                reg_map.pop(destination)
                            if reg_map == {} and memory_map == {}:
                                break
                        if sources[0] not in regtype and sources[1] not in regtype:
                            regtype[destination] = "interger"
                            if destination in reg_map:
                                reg_map.pop(destination)

        if mnemonic in {"load"}:#load指令的源参数是mem_addr
            rflags = 0
            mem_addr = sources[0]
            if len(base_registers)>0:
                base_register=base_registers[0]
                print(base_register,reg_map,regtype)
                if base_register in reg_map:
                    rflags=1
                    print(f"Decoded instruction at {hex(addr)}: {mnemonic},{base_registers},{mem_addr},{destination}")
                    print(f"[DEBUG] 寄存器映射+++: {destination} <-{mem_addr}<-{reg_map[base_register]}\n")
                    flow_info[reg_map[base_register]].append({
                        "address": hex(addr),
                        "mnemonic": mnemonic,
                        "type": "reg_to_mem",
                        "destination": destination,
                        "sources": mem_addr
                    })
                   # print("参数被用作基地址")
                    print(reg_map, regtype, memory_map)
                    regtype[base_register] = "pointer"
                    regtype[reg_map[base_register]] = "pointer"
                    param_types[reg_map[base_register]] = "pointer"
                    params[reg_map[base_register]] = "pointer"
                    print(reg_map, regtype, memory_map)
                    print(f"[INFO] 参数 {reg_map[base_register]} 的传播链: {flow_info[reg_map[base_register]]}\n")
                    reg_var = reg_map[base_register]
                    # print(reg_var)
                    if reg_var in inte_reg:
                        print(inte_reg[reg_var])
                        regtype[inte_reg[reg_var]] = "interger"
                        param_types[inte_reg[reg_var]] = "interger"
                        params[inte_reg[reg_var]] = "interger"
                        print(f"[INFO] 参数 {inte_reg[reg_var]} 的传播链: {flow_info[inte_reg[reg_var]]}\n")
                        reg_var2 = inte_reg[reg_var]
                        for mem in list(memory_map):
                            if memory_map[mem] == reg_var2:
                                memory_map_type[mem] = regtype[reg_var2]
                                memory_map.pop(mem)
                        for reg in list(reg_map):
                            if reg_map[reg] == reg_var2:
                                reg_map.pop(reg)
                    if 'd'+reg_var in sub_inte_reg:
                        print(sub_inte_reg['d'+reg_var])
                        regtype[sub_inte_reg['d'+reg_var]] = "pointer"
                        param_types[sub_inte_reg['d'+reg_var]] = "pointer"
                        params[sub_inte_reg['d'+reg_var]] = "pointer"
                        print(f"[INFO] 参数 {sub_inte_reg['d'+reg_var]} 的传播链: {flow_info[sub_inte_reg['d'+reg_var]]}\n")
                        reg_var2=sub_inte_reg['d'+reg_var]
                        for mem in list(memory_map):
                            if memory_map[mem] == reg_var2:
                                memory_map_type[mem] = regtype[reg_var2]
                                memory_map.pop(mem)
                        for reg in list(reg_map):
                            if reg_map[reg] == reg_var2:
                                reg_map.pop(reg)
                    for mem in list(memory_map):
                        if memory_map[mem] == reg_map[base_register]:
                            memory_map_type[mem] = regtype[base_register]
                            memory_map.pop(mem)
                    for reg in list(reg_map):
                        if reg_map[reg]==reg_var:
                            regtype[reg]=regtype[reg_var]
                            reg_map.pop(reg)
                    if destination in regtype:
                        regtype.pop(destination)
                    if reg_map == {} and memory_map == {}:
                        break
                if base_register not in reg_map and rflags==0:
                    if mem_addr not in memory_map and destination not in reg_map:
                        print(hex(addr), destination, mem_addr, mnemonic)
                        print(reg_map,regtype,memory_map)
                        if mem_addr in memory_map_type:
                            print(memory_map_type[mem_addr])
                            regtype[destination] = memory_map_type[mem_addr]
                        elif destination in regtype:
                            regtype.pop(destination)
                        print(reg_map, regtype)
                    if mem_addr not in memory_map and destination in reg_map:# 实现内存数据向寄存器的传递
                        print(f"Decoded instruction at {hex(addr)}: {mnemonic},{base_registers},{mem_addr},{destination}")
                        print(f"****[DEBUG] 寄存器映射***: {destination} <-{mem_addr}\n")
                        print(reg_map, regtype,memory_map)
                        flow_info[reg_map[destination]].append({
                            "address": hex(addr),
                            "mnemonic": mnemonic,
                            "type": "mem_to_reg",
                            "destination": destination,
                            "sources": mem_addr
                        })
                        if mem_addr in memory_map_type:
                            print(memory_map_type[mem_addr])
                            regtype[destination]=memory_map_type[mem_addr]
                        if mem_addr not in memory_map_type and destination in regtype:
                            regtype.pop(destination)
                        reg_map.pop(destination)
                        print(reg_map, regtype)
                    if mem_addr in memory_map and destination in reg_map:  # 实现内存数据向寄存器的传递例如sp作为基地址
                        print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                        print(reg_map,regtype)
                        print(memory_map)
                        reg_map[destination] = memory_map[mem_addr]  # 更新目标寄存器的来源
                        print(f"[DEBUG] ******寄存器映射: {destination} <-{mem_addr}\n")
                        flow_info[memory_map[mem_addr]].append({
                            "address": hex(addr),
                            "mnemonic": mnemonic,
                            "type": "mem_to_reg",
                            "destination": destination,
                            "sources": mem_addr
                        })
                        if mem_addr in memory_map_type:
                            regtype[destination] = memory_map_type[mem_addr]
                        if mem_addr not in memory_map_type and destination in regtype:
                            regtype.pop(destination)
                        print(reg_map,regtype)
                    if mem_addr in memory_map and destination not in reg_map:  # 实现内存数据向寄存器的传递例如sp作为基地址
                        print(reg_map,memory_map)
                        print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                        print(f"[DEBUG] ******寄存器映射: {destination} <-{mem_addr}-<{memory_map[mem_addr]}\n")
                        print(reg_map, memory_map)
                        reg_map[destination] = memory_map[mem_addr]  # 更新目标寄存器的来源
                        flow_info[memory_map[mem_addr]].append({
                            "address": hex(addr),
                            "mnemonic": mnemonic,
                            "type": "mem_to_reg",
                            "destination": destination,
                            "sources": mem_addr
                        })
                        if mem_addr in memory_map_type:
                            print(memory_map_type[mem_addr])
                            regtype[destination] = memory_map_type[mem_addr]
                        if mem_addr not in memory_map_type and destination in regtype:
                            regtype.pop(destination)
                        print(reg_map, memory_map)
        if mnemonic in {"load_int"}:#load指令的源参数是mem_addr,bas_register
            rflags=0
            mem_addr = sources[0]
            if len(base_registers)>0:
                base_register=base_registers[0]
                if base_register in reg_map:
                    rflags=1
                    print(reg_map,regtype,memory_map,inte_reg)
                    print(f"Decoded instruction at {hex(addr)}: {mnemonic},{base_registers},{mem_addr},{destination}")
                    print(f"[DEBUG] 寄存器映射+++: {destination} <-{mem_addr}<-{reg_map[base_register]}\n")
                    flow_info[reg_map[base_register]].append({
                        "address": hex(addr),
                        "mnemonic": mnemonic,
                        "type": "reg_to_mem",
                        "destination": destination,
                        "sources": mem_addr
                    })
                   # print("参数被用作基地址")
                    regtype[base_register] = "pointer"
                    regtype[reg_map[base_register]] = "pointer"
                    param_types[reg_map[base_register]] = "pointer"
                    params[reg_map[base_register]] = "pointer"
                    if idc.print_insn_mnem(addr) in {"lb"}:
                        regtype[destination] = "interger"
                    if idc.print_insn_mnem(addr) in {"lbu"}:
                        regtype[destination] = "interger"
                    if idc.print_insn_mnem(addr) in {"lh"}:
                        regtype[destination] = "interger"
                    if idc.print_insn_mnem(addr) in {"lhu"}:
                        regtype[destination] = "interger"
                    print(reg_map, regtype, memory_map,inte_reg)
                    print(f"[INFO] 参数 {reg_map[base_register]} 的传播链: {flow_info[reg_map[base_register]]}\n")
                    reg_var=reg_map[base_register]
                    #print(reg_var)
                    if 'd'+reg_var in sub_inte_reg:
                        print(sub_inte_reg['d'+reg_var])
                        regtype[sub_inte_reg['d'+reg_var]] = "pointer"
                        param_types[sub_inte_reg['d'+reg_var]] = "pointer"
                        params[sub_inte_reg['d'+reg_var]] = "pointer"
                        print(f"[INFO] 参数 {sub_inte_reg['d'+reg_var]} 的传播链: {flow_info[sub_inte_reg['d'+reg_var]]}\n")
                        reg_var2=sub_inte_reg['d'+reg_var]
                        for mem in list(memory_map):
                            if memory_map[mem] == reg_var2:
                                memory_map_type[mem] = regtype[reg_var2]
                                memory_map.pop(mem)
                        for reg in list(reg_map):
                            if reg_map[reg] == reg_var2:
                                reg_map.pop(reg)


                    if reg_var in inte_reg:
                        print(inte_reg[reg_var])
                        regtype[inte_reg[reg_var]] = "interger"
                        param_types[inte_reg[reg_var]] = "interger"
                        params[inte_reg[reg_var]] = "interger"
                        print(f"[INFO] 参数 {inte_reg[reg_var]} 的传播链: {flow_info[inte_reg[reg_var]]}\n")
                        reg_var2=inte_reg[reg_var]
                        for mem in list(memory_map):
                            if memory_map[mem] == reg_var2:
                                memory_map_type[mem] = regtype[reg_var2]
                                memory_map.pop(mem)
                        for reg in list(reg_map):
                            if reg_map[reg] == reg_var2:
                                reg_map.pop(reg)
                    for mem in list(memory_map):
                        if memory_map[mem] == reg_var:
                            memory_map_type[mem] = regtype[base_register]
                            memory_map.pop(mem)
                    for reg in list(reg_map):
                        if reg_map[reg]==reg_var and reg!=destination:
                            regtype[reg]=regtype[reg_var]
                            reg_map.pop(reg)
                    if destination in reg_map:
                        reg_map.pop(destination)
                    if reg_map == {} and memory_map == {}:
                        break
                if base_register not in reg_map and rflags==0:
                    if mem_addr not in memory_map and destination not in reg_map:
                        regtype[destination] = "interger"
                        print(reg_map,regtype)
                    if mem_addr not in memory_map and destination in reg_map:  # 实现内存数据向寄存器的传递
                        print(f"Decoded instruction at {hex(addr)}: {mnemonic},{base_registers},{mem_addr},{destination}")
                        print(f"[DEBUG] 寄存器映射***: {destination} <-{mem_addr}\n")
                        print("regtype:",regtype)
                        flow_info[reg_map[destination]].append({
                            "address": hex(addr),
                            "mnemonic": mnemonic,
                            "type": "mem_to_reg",
                            "destination": destination,
                            "sources": mem_addr
                        })
                        regtype[destination]="interger"
                        reg_map.pop(destination)
                        print(reg_map,regtype)
                    if mem_addr in memory_map and destination in reg_map:  # 实现内存数据向寄存器的传递例如sp作为基地址
                        print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                        print("regtype:",regtype)
                        reg_map[destination] = memory_map[mem_addr]  # 更新目标寄存器的来源
                        print(f"[DEBUG] ******寄存器映射: {destination} <-{mem_addr}\n")
                        flow_info[memory_map[mem_addr]].append({
                            "address": hex(addr),
                            "mnemonic": mnemonic,
                            "type": "mem_to_reg",
                            "destination": destination,
                            "sources": mem_addr
                        })
                        regtype[destination]="interger"
                        print(reg_map,regtype)
                    if mem_addr in memory_map and destination not in reg_map:  # 实现内存数据向寄存器的传递例如sp作为基地址
                        print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                        print(reg_map,regtype)
                        reg_map[destination] = memory_map[mem_addr]  # 更新目标寄存器的来源
                        print(f"[DEBUG] ******寄存器映射: {destination} <-{mem_addr}-<{memory_map[mem_addr]}\n")
                        flow_info[reg_map[destination]].append({
                            "address": hex(addr),
                            "mnemonic": mnemonic,
                            "type": "mem_to_reg",
                            "destination": destination,
                            "sources": mem_addr
                        })
                        regtype[destination]="interger"
                        print(reg_map,regtype)

        if mnemonic in {"arithmetic_move"}:#move
            if sources[0] not in reg_map and destination not in reg_map:
                src_reg=sources[0]
                print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                print(reg_map, regtype)
                if sources[0] in regtype:
                    regtype[destination] = regtype[sources[0]]
                if sources[0] not in regtype:
                    if sources[0]=="$zero":
                        regtype[destination] = "interger"
                    if sources[0]!="$zero" and destination in regtype:
                        regtype.pop(destination)
                print(reg_map, regtype)
            if sources[0] in reg_map and destination in reg_map:  # 仅追踪来源于当前参数的寄存器
                print(hex(addr),destination,sources)
                print(reg_map,regtype)
                src_reg = sources[0]
                reg_map[destination] = reg_map[src_reg]
                print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                print(f"[DEBUG] 记录寄存器映射: {destination} <-{src_reg} <-{reg_map[src_reg]}\n")
                print(reg_map, regtype)
                flow_info[reg_map[src_reg]].append({
                    "address": hex(addr),
                    "mnemonic": mnemonic,
                    "type": "reg_to_reg",
                    "destination": destination,
                    "sources": src_reg
                })
                if sources[0] in regtype:
                    regtype[destination] = regtype[sources[0]]
                    regtype[reg_map[sources[0]]]=regtype[sources[0]]
                    param_types[reg_map[sources[0]]] = regtype[sources[0]]
                    params[reg_map[sources[0]]] = regtype[sources[0]]
                    print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                    reg_var = reg_map[src_reg]
                    for mem in list(memory_map):
                        if memory_map[mem] == reg_map[src_reg]:
                            memory_map_type[mem] = regtype[src_reg]
                            memory_map.pop(mem)
                    for reg in list(reg_map):
                        if reg_map[reg]==reg_var:
                            regtype[reg]=regtype[reg_var]
                            reg_map.pop(reg)
                    if reg_map == {} and memory_map == {}:
                        break
                if sources[0] not in regtype and destination in regtype:
                    regtype.pop(destination)
            if sources[0] not in reg_map and destination in reg_map:  # 仅追踪来源于当前参数的寄存器
                print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                print(f"[DEBUG] 记录寄存器映射: {destination} <- {sources}\n")
                print(reg_map,regtype)
                flow_info[reg_map[destination]].append({
                    "address": hex(addr),
                    "mnemonic": mnemonic,
                    "type": "reg_to_reg",
                    "destination": destination,
                    "sources": sources
                })
                if sources[0] in regtype:
                    regtype[destination] = regtype[sources[0]]
                if sources[0] not in regtype and destination in regtype:
                     regtype.pop(destination)
                reg_map.pop(destination)

            if sources[0] in reg_map and destination not in reg_map:  # 仅追踪来源于当前参数的寄存器
                print(hex(addr),destination,sources)
                src_reg = sources[0]
                reg_map[destination] = reg_map[src_reg]
                print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                print(f"[DEBUG] 记录寄存器映射: {destination} <-{src_reg} <-{reg_map[src_reg]}\n")
                print(reg_map, regtype)
                flow_info[reg_map[src_reg]].append({
                    "address": hex(addr),
                    "mnemonic": mnemonic,
                    "type": "reg_to_reg",
                    "destination": destination,
                    "sources": src_reg
                })
                if sources[0] in regtype:
                    regtype[destination] = regtype[sources[0]]
                    regtype[reg_map[sources[0]]]=regtype[sources[0]]
                    param_types[reg_map[sources[0]]] = regtype[sources[0]]
                    params[reg_map[sources[0]]] = regtype[sources[0]]
                    print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                    reg_var = reg_map[src_reg]
                    for mem in list(memory_map):
                        if memory_map[mem] == reg_map[src_reg]:
                            memory_map_type[mem] = regtype[src_reg]
                            memory_map.pop(mem)
                    for reg in list(reg_map):
                        if reg_map[reg]==reg_var:
                            regtype[reg]=regtype[reg_var]
                            reg_map.pop(reg)
                    if reg_map == {} and memory_map == {}:
                        break
                if sources[0] not in regtype and destination in regtype:
                    regtype.pop(destination)

        if mnemonic in {"conditional_move"}:#move
            if sources[0] not in reg_map and destination not in reg_map:  # 仅追踪来源于当前参数的寄存器
                print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                print(f"[DEBUG] 记录寄存器映射: {destination} <- {sources}\n")
                if sources[0] in regtype:
                    regtype[destination] = regtype[sources[0]]
                if sources[0]=="$zero":
                    regtype[sources[0]] = "interger"
                    regtype[destination] = "interger"

            if sources[0] not in reg_map and destination in reg_map:  # 仅追踪来源于当前参数的寄存器
                print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                print(f"[DEBUG] 记录寄存器映射: {destination} <- {sources}\n")
                print(reg_map,regtype)
                flow_info[reg_map[destination]].append({
                    "address": hex(addr),
                    "mnemonic": mnemonic,
                    "type": "reg_to_reg",
                    "destination": destination,
                    "sources": sources
                })
                if sources[0] in regtype:
                    regtype[destination] = regtype[sources[0]]
                if sources[0]=="$zero":
                    regtype[destination] = "interger"
                    # param_types[reg_map[destination]] = "interger"
                    # param_types[reg_map[destination]] = "interger"
                print(reg_map, regtype)
                reg_map.pop(destination)

            if sources[0] in reg_map and destination not in reg_map:  # 仅追踪来源于当前参数的寄存器
                src_reg = sources[0]
                reg_map[destination] = reg_map[src_reg]
                print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                print(f"[DEBUG] 记录寄存器映射: {destination} <-{src_reg} <-{reg_map[src_reg]}\n")
                print(reg_map, regtype)
                flow_info[reg_map[src_reg]].append({
                    "address": hex(addr),
                    "mnemonic": mnemonic,
                    "type": "reg_to_reg",
                    "destination": destination,
                    "sources": sources
                })
                if sources[0] in regtype:
                    regtype[destination] = regtype[sources[0]]
                    param_types[reg_map[sources[0]]] = regtype[sources[0]]
                    params[reg_map[sources[0]]] = regtype[sources[0]]
                    regtype[reg_map[src_reg]] = regtype[src_reg]
                    print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                    reg_var = reg_map[src_reg]
                    for mem in list(memory_map):
                        if memory_map[mem] == reg_map[src_reg]:
                            memory_map_type[mem] = regtype[src_reg]
                            memory_map.pop(mem)
                    for reg in list(reg_map):
                        if reg_map[reg] == reg_var:
                            regtype[reg] = regtype[reg_var]
                            reg_map.pop(reg)
                    if reg_map == {} and memory_map == {}:
                        break
                if sources[0] not in regtype and destination in regtype:
                    regtype.pop(destination)
            if sources[0] in reg_map and destination in reg_map:  # 仅追踪来源于当前参数的寄存器
                src_reg = sources[0]
                reg_map[destination] = reg_map[src_reg]
                print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                print(f"[DEBUG] 记录寄存器映射: {destination} <-{src_reg} <-{reg_map[src_reg]}\n")
                print(reg_map, regtype)
                flow_info[reg_map[src_reg]].append({
                    "address": hex(addr),
                    "mnemonic": mnemonic,
                    "type": "reg_to_reg",
                    "destination": destination,
                    "sources": sources
                })
                if sources[0] in regtype:
                    regtype[destination] = regtype[ssrc_reg]
                    param_types[reg_map[src_reg]] = regtype[src_reg]
                    params[reg_map[src_reg]] = regtype[src_reg]
                    regtype[reg_map[src_reg]]=regtype[src_reg]
                    print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                    reg_var = reg_map[src_reg]
                    for mem in list(memory_map):
                        if memory_map[mem] == reg_map[src_reg]:
                            memory_map_type[mem] = regtype[src_reg]
                            memory_map.pop(mem)
                    for reg in list(reg_map):
                        if reg_map[reg] == reg_var:
                            regtype[reg] = regtype[reg_var]
                            reg_map.pop(reg)
                    if reg_map == {} and memory_map == {}:
                        break
                if sources[0] not in regtype and destination in regtype:
                    regtype.pop(destination)

                reg_map.pop(destination)
        if mnemonic in {"move_float"}:
            src_reg = sources[0]
            if src_reg not in reg_map:  # 仅追踪来源于当前参数的寄存器
                print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                regtype[sources[0]] = "interger"

            if src_reg in reg_map:  # 仅追踪来源于当前参数的寄存器
                print(f"[DEBUG] 记录寄存器映射: {destination} <-{src_reg} <-{reg_map[src_reg]}\n")
                flow_info[reg_map[src_reg]].append({
                    "address": hex(addr),
                    "mnemonic": mnemonic,
                    "type": "reg_to_reg",
                    "destination": destination,
                    "sources": sources
                })
                regtype[src_reg] = "interger"
                regtype[reg_map[src_reg]] = "interger"
                param_types[reg_map[src_reg]] = "interger"
                params[reg_map[src_reg]] = "interger"
                print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                reg_var = reg_map[src_reg]
                for mem in list(memory_map):
                    if memory_map[mem] == reg_map[src_reg]:
                        memory_map_type[mem] = regtype[src_reg]
                        memory_map.pop(mem)
                for reg in list(reg_map):
                    if reg_map[reg] == reg_var:
                        regtype[reg] = regtype[reg_var]
                        reg_map.pop(reg)
                if reg_map == {} and memory_map == {}:
                    break
        if mnemonic in {"arithmetic_with_la"}:
            print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
            print(f"[DEBUG] 记录寄存器映射: {destination} <- {sources}\n")
            mem_addr=sources[0]
            if destination in reg_map:
                flow_info[reg_map[destination]].append({
                    "address": hex(addr),
                    "mnemonic": mnemonic,
                    "type": "la_to_reg",
                    "destination": destination,
                    "sources": sources[0]
                })
                regtype[destination] = "pointer"
                reg_map.pop(destination)
                print(reg_map, regtype)
            if destination not in reg_map:
                regtype[destination] = "pointer"

        if mnemonic in {"arithmetic_with_imm"}:#整型或者指针，具体跟立即数数的范围又关系，li,lui
            print(f"[DEBUG] 记录寄存器映射: {destination} <- {sources}\n")
            print(reg_map,regtype)
            if start_address<imm<end_address:
                regtype[destination] = "pointer"
            else:
                regtype[destination] = "interger"
            if destination in reg_map:
                flow_info[reg_map[destination]].append({
                    "address": hex(addr),
                    "mnemonic": mnemonic,
                    "type": "reg_to_reg",
                    "destination": destination,
                    "sources": hex(imm)
                })
                reg_map.pop(destination)
            print(reg_map,regtype)

        if mnemonic in {"arithmetic","bitoperate"}:
            #print(hex(addr),mnemonic,len(sources),sources[0],destination)
            # if destination not in reg_map and all(src not in reg_map for src in sources):
            #     print("continue",hex(addr),mnemonic)
            #     continue
            cflag=0
            if imm!=None:
                imm = signed_hex_to_decimal(imm)
                print(hex(addr), imm)
                prev_ea = idc.prev_head(addr)
                next_ea= idc.next_head(addr)
                mnemonic_prev=idc.print_insn_mnem(prev_ea)
                mnemonic_next = idc.print_insn_mnem(next_ea)
                opnd_prev = idc.print_operand(prev_ea, 0)
                opnd_next = idc.print_operand(prev_ea, 0)
                print(hex(prev_ea),mnemonic_prev)

                if len(sources) == 1:
                    if destination in reg_map:
                        print(f"[DEBUG] 记录寄存器映射: {destination} <- {sources}\n")
                        print(reg_map,regtype)
                        flow_info[reg_map[destination]].append({
                            "address": hex(addr),
                            "mnemonic": mnemonic,
                            "type": "reg_to_reg",
                            "destination": destination,
                            "sources": sources[0]
                        })
                        print("参数参数数学运算，寄存器的值被修改了")
                        if imm < 0 and ((mnemonic_prev in {"bgezal","bgez","blez","beqz","beqzl","bnez","bc1t","bc1f"} and opnd_prev==destination) or (mnemonic_next in {"bgezal","bgez","blez","beqz","beqzl","bnez","bc1t","bc1f"} and opnd_next==destination)):
                            regtype[destination] = "interger"
                            regtype[reg_map[destination]] = "interger"
                            param_types[reg_map[destination]] = "interger"
                            params[reg_map[destination]] = "interger"
                            print(f"[INFO] 参数 {reg_map[destination]} 的传播链: {flow_info[reg_map[destination]]}\n")
                            reg_var = reg_map[destination]
                            for mem in list(memory_map):
                                if memory_map[mem] == reg_map[destination]:
                                    memory_map_type[mem] = regtype[destination]
                                    memory_map.pop(mem)
                            for reg in list(reg_map):
                                if reg_map[reg] == reg_var:
                                    regtype[reg] = regtype[reg_var]
                                    reg_map.pop(reg)
                            if reg_map == {} and memory_map == {}:
                                break

                        elif destination in regtype:
                            param_types[reg_map[destination]] = regtype[destination]
                            params[reg_map[destination]] = regtype[destination]
                            print(reg_map, regtype)
                            if reg_map[destination] in reg_map:
                                reg_map.pop(reg_map[destination])
                            if destination in reg_map:
                                print(f"[INFO] 参数 {reg_map[destination]} 的传播链: {flow_info}\n")
                                reg_map.pop(destination)
                            if reg_map == {} and memory_map == {}:
                                break
                if len(sources) == 2:  ###????????算术运算的传播问题,存在立即数
                    if destination not in reg_map:
                        if sources[0] in reg_map:
                            print(reg_map,regtype)
                            src_reg = sources[0]
                            #reg_map[destination] = reg_map[src_reg]
                            #print(reg_map)
                            cflag = 1
                            print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                            print(f"[DEBUG] 记录寄存器映射: {destination} <- {reg_map[src_reg]}->{sources}\n")
                            reg_map[destination] = reg_map[src_reg]
                            flow_info[reg_map[src_reg]].append({
                                "address": hex(addr),
                                "mnemonic": mnemonic,
                                "type": "reg_to_reg",
                                "destination": destination,
                                "sources": sources
                            })
                            if imm < 0 and ((mnemonic_prev in {"bgezal", "bgez", "blez", "beqz", "beqzl", "bnez",
                                                               "bc1t", "bc1f"} and opnd_prev == destination) or (
                                                    mnemonic_next in {"bgezal", "bgez", "blez", "beqz", "beqzl", "bnez",
                                                                      "bc1t", "bc1f"} and opnd_next == destination)):
                                regtype[src_reg] = "interger"
                                regtype[reg_map[src_reg]] = "interger"
                                param_types[reg_map[src_reg]] = "interger"
                                params[reg_map[src_reg]] = "interger"
                                print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                                reg_var = reg_map[src_reg]
                                for mem in list(memory_map):
                                    if memory_map[mem] == reg_map[src_reg]:
                                        memory_map_type[mem] = regtype[src_reg]
                                        memory_map.pop(mem)
                                for reg in list(reg_map):
                                    if reg_map[reg] == reg_var:
                                        regtype[reg] = regtype[reg_var]
                                        reg_map.pop(reg)
                                if reg_map == {} and memory_map == {}:
                                    break
                            # print("参数可能是整型")
                            else:
                                if src_reg=="$fp":
                                    regtype[destination] = "pointer"
                                if src_reg in regtype:
                                    param_types[reg_map[src_reg]] = regtype[src_reg]
                                    params[reg_map[src_reg]] = regtype[src_reg]
                                    regtype[destination] = regtype[src_reg]
                                    print(reg_map,regtype)
                                    if reg_map[src_reg] in reg_map:
                                        reg_map.pop(reg_map[src_reg])
                                    if src_reg in reg_map:
                                        print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                                        reg_map.pop(src_reg)
                                    if reg_map=={} and memory_map=={}:
                                        break
                                if src_reg not in regtype and destination in regtype:
                                        regtype.pop(destination)
                                        print(reg_map, regtype)
                        if sources[0] not in reg_map:#源寄存器，imm
                            print(reg_map,regtype)
                            print(hex(addr),sources[0])
                            src_reg = sources[0]
                            if imm == -1:
                                regtype[destination]="interger"
                                regtype[src_reg] = "interger"
                            else:
                                if src_reg=="$fp":
                                    regtype[destination] = "pointer"
                                if src_reg in regtype:
                                    regtype[destination] = regtype[src_reg]
                                    print(reg_map,regtype)
                                if src_reg not in regtype and destination in regtype:
                                    regtype.pop(destination)
                    if destination in reg_map and cflag == 0:
                        if sources[0] in {"$sp"}:
                            # regtype[destination] = "pointer"
                            # regtype[reg_map[destination]] = "pointer"
                            # param_types[reg_map[destination]] = "pointer"
                            # print(f"[INFO] 参数 {reg_map[destination]} 的传播链: {flow_info[reg_map[destination]]}\n")
                            # reg_var = reg_map[destination]
                            # for mem in list(memory_map):
                            #     if memory_map[mem] == reg_var:
                            #         memory_map_type[mem] = regtype[destination]
                            #         memory_map.pop(mem)
                            # for reg in list(reg_map):
                            #     if reg_map[reg] == reg_var:
                            #         regtype[reg] = regtype[reg_var]
                            #         reg_map.pop(reg)
                            # if reg_map == {} and memory_map == {}:
                            #     break
                            continue
                        elif sources[0] not in reg_map:  # 仅追踪来源于当前参数的寄存器
                            src_reg=sources[0]
                            print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                            print(f"[DEBUG] 记录寄存器映射: {destination} <- {sources}\n")
                            print(reg_map,regtype)
                            flow_info[reg_map[destination]].append({
                                "address": hex(addr),
                                "mnemonic": mnemonic,
                                "type": "reg_to_reg",
                                "destination": destination,
                                "sources": sources
                            })
                            if src_reg == "$fp":
                                regtype[destination] = "pointer"
                            if sources[0] in regtype:
                                regtype[destination] = regtype[sources[0]]
                                #param_types[reg_map[destination]] = regtype[destination]
                            if destination in reg_map:
                                    reg_map.pop(destination)
                            print(reg_map,regtype)
                        elif sources[0] in reg_map:  # 仅追踪来源于当前参数的寄存器
                            src_reg=sources[0]
                            print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                            print(f"[DEBUG] 记录寄存器映射: {destination} <- {sources}\n")
                            print(reg_map,regtype)
                            reg_map[destination] = reg_map[src_reg]
                            flow_info[reg_map[destination]].append({
                                "address": hex(addr),
                                "mnemonic": mnemonic,
                                "type": "reg_to_reg",
                                "destination": destination,
                                "sources": sources
                            })
                            if sources[0] in regtype:
                                regtype[destination] = regtype[sources[0]]
                                param_types[reg_map[sources[0]]] = regtype[sources[0]]
                                params[reg_map[sources[0]]] = regtype[sources[0]]
                                print(reg_map,regtype)
                                print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                                reg_var = reg_map[src_reg]
                                for mem in list(memory_map):
                                    if memory_map[mem] == reg_map[src_reg]:
                                        memory_map_type[mem] = regtype[src_reg]
                                        memory_map.pop(mem)
                                for reg in list(reg_map):
                                    if reg_map[reg]==reg_var:
                                        regtype[reg]=regtype[reg_var]
                                        reg_map.pop(reg)
                                if reg_map == {} and memory_map == {}:
                                    break
                            if sources[0] not in regtype and destination in regtype:
                                regtype.pop(destination)

            if imm==None:
                if len(sources) ==1:
                    print(hex(addr),reg_map)

                    if destination in reg_map:#不传播,由已知计算未知
                        cflag=1
                        if sources[0] not in reg_map:
                            print(f"[DEBUG] 记录寄存器映射: {destination} <- {sources}\n")
                            print("regtype:",regtype)
                            flow_info[reg_map[destination]].append({
                                "address": hex(addr),
                                "mnemonic": mnemonic,
                                "type": "reg_to_reg",
                                "destination": destination,
                                "sources": sources[0]
                            })
                            print("参数参数数学运算，寄存器的值被修改了")
                            if sources[0] in regtype and regtype[sources[0]] == "pointer":
                                regtype[reg_map[destination]] = "interger"
                                param_types[reg_map[destination]] = "interger"
                                params[reg_map[destination]] = "interger"
                                regtype[destination] = "pointer"
                                #reg_map[destination] = reg_map[sources[0]]
                                print(reg_map, regtype)
                                print(f"[INFO] 参数 {reg_map[destination]} 的传播链: {flow_info[reg_map[destination]]}\n")
                                reg_var = reg_map[destination]
                                for mem in list(memory_map):
                                    if memory_map[mem] == reg_map[destination]:
                                        memory_map_type[mem] = regtype[destination]
                                        memory_map.pop(mem)
                                for reg in list(reg_map):
                                    if reg_map[reg] == reg_var:
                                        regtype[reg] = regtype[reg_var]
                                        reg_map.pop(reg)
                                if destination in reg_map:
                                    reg_map.pop(destination)
                                if reg_map == {} and memory_map == {}:
                                    break
                        if sources[0] in reg_map:
                            print(f"**********[DEBUG] 记录寄存器映射**********: {destination} <- {sources}\n")
                            src_reg = sources[0]
                            print("regtype:",regtype)
                            if destination in regtype:
                                print(regtype[destination])

                            #reg_map[destination] = reg_map[src_reg]
                            flow_info[reg_map[destination]].append({
                                "address": hex(addr),
                                "mnemonic": mnemonic,
                                "type": "reg_to_reg",
                                "destination": destination,
                                "sources": sources[0]
                            })
                            #print("寄存器的值被修改了")
                            if sources[0] not in regtype and destination not in regtype:
                                inte_reg[reg_map[destination]] = reg_map[sources[0]]
                                inte_reg[reg_map[sources[0]]] = reg_map[destination]
                                #reg_map[destination] = reg_map[sources[0]]

                            if sources[0] in regtype and regtype[sources[0]] == "pointer":
                                regtype[reg_map[destination]] = "interger"
                                param_types[reg_map[destination]] = "interger"
                                params[reg_map[destination]] = "interger"
                                reg_map[destination] = reg_map[sources[0]]
                                regtype[destination] = "pointer"
                                print(reg_map, regtype)
                                print(f"[INFO] 参数 {reg_map[destination]} 的传播链: {flow_info[reg_map[destination]]}\n")
                                reg_var = reg_map[destination]
                                for mem in list(memory_map):
                                    if memory_map[mem] == reg_map[destination]:
                                        memory_map_type[mem] = regtype[destination]
                                        memory_map.pop(mem)
                                for reg in list(reg_map):
                                    if reg_map[reg] == reg_var:
                                        regtype[reg] = regtype[reg_var]
                                        reg_map.pop(reg)
                                if reg_map == {} and memory_map == {}:
                                    break
                            if destination in regtype and regtype[destination] == "pointer":
                                regtype[src_reg]="interger"
                                regtype[reg_map[src_reg]] = "interger"
                                param_types[reg_map[src_reg]] = "interger"
                                params[reg_map[src_reg]] = "interger"
                                print(reg_map,regtype)
                                print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                                reg_var = reg_map[src_reg]
                                for mem in list(memory_map):
                                    if memory_map[mem] == reg_map[src_reg]:
                                        memory_map_type[mem] = regtype[src_reg]
                                        memory_map.pop(mem)
                                for reg in list(reg_map):
                                    if reg_map[reg] == reg_var:
                                        regtype[reg] = regtype[reg_var]
                                        reg_map.pop(reg)
                                if reg_map == {} and memory_map == {}:
                                    break
                    if destination not in reg_map and cflag==0:#也不传递
                        if sources[0] in reg_map :  # 仅追踪来源于当前参数的寄存器,两个参数的情况
                            src_reg = sources[0]
                            print(f"[DEBUG] 记录寄存器映射: {destination} <- {reg_map[src_reg]}\n")
                            print(reg_map, regtype)
                            flow_info[reg_map[src_reg]].append({
                                "address": hex(addr),
                                "mnemonic": mnemonic,
                                "type": "reg_to_reg",
                                "destination": destination,
                                "sources": sources[0]
                            })
                            if destination in regtype and regtype[destination] == "pointer":
                                regtype[src_reg] = "interger"
                                regtype[reg_map[src_reg]] = "interger"
                                param_types[reg_map[src_reg]] = "interger"
                                params[reg_map[src_reg]] = "interger"
                                print(reg_map, regtype)
                                print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                                reg_var = reg_map[src_reg]
                                for mem in list(memory_map):
                                    if memory_map[mem] == reg_map[src_reg]:
                                        memory_map_type[mem] = regtype[src_reg]
                                        memory_map.pop(mem)
                                for reg in list(reg_map):
                                    if reg_map[reg] == reg_var:
                                        regtype[reg] = regtype[reg_var]
                                        reg_map.pop(reg)
                                if reg_map == {} and memory_map == {}:
                                    break
                            if destination in regtype and regtype[destination] != "pointer":
                                reg_map[destination] = reg_map[src_reg]
                                regtype.pop(destination)
                            if destination not in regtype:
                                reg_map[destination] = reg_map[sources[0]]
                        if sources[0] not in reg_map:
                            src_reg = sources[0]
                            if src_reg in regtype and regtype[src_reg] == "pointer":
                                regtype[destination] = "pointer"
                            if destination in regtype and regtype[destination] == "pointer":
                                regtype[src_reg] = "interger"

                if len(sources) ==2:###????????算术运算的传播问题,参数类型
                    print(destination,sources)
                    if destination not in reg_map:
                        cflag=1
                        if sources[0] in reg_map and sources[1] in reg_map:
                            print(hex(addr),sources[0])
                            #print(regtype[sources[1]])
                            src_reg = sources[0]
                            #if destination not in sources:
                            print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                            print(f"[DEBUG] 记录寄存器映射: {destination} <- {reg_map[src_reg]}->{sources}\n")
                            print(reg_map,regtype)
                            flow_info[reg_map[src_reg]].append({
                                "address": hex(addr),
                                "mnemonic": mnemonic,
                                "type": "reg_to_reg",
                                "destination": destination,
                                "sources": sources
                            })

                            if sources[1] in regtype and regtype[sources[1]] == "pointer":
                                regtype[src_reg] = "interger"
                                param_types[reg_map[src_reg]]="interger"
                                params[reg_map[src_reg]] = "interger"
                                regtype[reg_map[src_reg]] = "interger"
                                regtype[destination] = "pointer"
                                print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                                reg_var = reg_map[src_reg]
                                for mem in list(memory_map):
                                    if memory_map[mem] == reg_map[src_reg]:
                                        memory_map_type[mem] = regtype[src_reg]
                                        memory_map.pop(mem)
                                for reg in list(reg_map):
                                    if reg_map[reg]==reg_var:
                                        regtype[reg]=regtype[reg_var]
                                        reg_map.pop(reg)
                                if reg_map == {} and memory_map == {}:
                                    break
                            if sources[0] in regtype and regtype[sources[0]]=="pointer":
                                reg_map[destination]=reg_map[src_reg]

                                regtype[reg_map[sources[1]]] = "interger"
                                regtype[destination]="pointer"
                                regtype[sources[1]]="interger"
                                param_types[reg_map[sources[1]]]="interger"
                                params[reg_map[sources[1]]] = "interger"
                                print(f"[INFO] 参数 {reg_map[sources[1]]} 的传播链: {flow_info[reg_map[sources[1]]]}\n")
                                reg_var = reg_map[sources[1]]
                                for mem in list(memory_map):
                                    if memory_map[mem] == reg_var:
                                        memory_map_type[mem] = regtype[sources[1]]
                                        memory_map.pop(mem)
                                for reg in list(reg_map):
                                    if reg_map[reg]==reg_var:
                                        regtype[reg]=regtype[reg_var]
                                        reg_map.pop(reg)
                                if reg_map == {} and memory_map == {}:
                                    break
                            if sources[1] in regtype and regtype[sources[1]]!= "pointer":
                                reg_map[destination] = reg_map[sources[0]]
                                if destination in regtype:
                                    regtype.pop(destination)
                            if sources[0] in regtype and regtype[sources[0]]!= "pointer":
                                reg_map[destination] = reg_map[sources[1]]
                                if destination in regtype:
                                    regtype.pop(destination)
                            if sources[0] not in regtype and sources[1] not in regtype:
                                inte_reg[reg_map[sources[0]]] = reg_map[sources[1]]
                                inte_reg[reg_map[sources[1]]] = reg_map[sources[0]]
                                #reg_map[destination] = reg_map[sources[0]]
                                if destination in regtype:
                                    regtype.pop(destination)

                        if sources[0] in reg_map and sources[1] not in reg_map:
                            cflag=1
                            print(hex(addr),sources[0])
                            #print(regtype[sources[1]])
                            src_reg = sources[0]
                            #if destination not in sources:
                            print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                            print(f"[DEBUG] 记录寄存器映射: {destination} <- {reg_map[src_reg]}->{sources}\n")
                            print(reg_map,regtype)
                            flow_info[reg_map[src_reg]].append({
                                "address": hex(addr),
                                "mnemonic": mnemonic,
                                "type": "reg_to_reg",
                                "destination": destination,
                                "sources": sources
                            })

                            if sources[1] in regtype and regtype[sources[1]] == "pointer":
                                regtype[src_reg] = "interger"
                                param_types[reg_map[src_reg]]="interger"
                                params[reg_map[src_reg]] = "interger"
                                regtype[reg_map[src_reg]] = "interger"
                                regtype[destination] = "pointer"
                                print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                                reg_var = reg_map[src_reg]
                                for mem in list(memory_map):
                                    if memory_map[mem] == reg_map[src_reg]:
                                        memory_map_type[mem] = regtype[src_reg]
                                        memory_map.pop(mem)
                                for reg in list(reg_map):
                                    if reg_map[reg]==reg_var:
                                        regtype[reg]=regtype[reg_var]
                                        reg_map.pop(reg)
                                if reg_map == {} and memory_map == {}:
                                    break
                            if sources[1] in regtype and regtype[sources[1]] != "pointer":
                                reg_map[destination] = reg_map[src_reg]
                                if destination in regtype:
                                    regtype.pop(destination)
                            if sources[1] not in regtype:
                                reg_map[destination] = reg_map[src_reg]

                        if sources[0] not in reg_map and sources[1] in reg_map:
                            src_reg = sources[1]
                            print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                            print(f"[DEBUG] 记录寄存器映射: {destination} <- {reg_map[src_reg]}->{sources}\n")
                            print(reg_map,regtype)

                            flow_info[reg_map[src_reg]].append({
                                "address": hex(addr),
                                "mnemonic": mnemonic,
                                "type": "reg_to_reg",
                                "destination": destination,
                                "sources": sources
                            })
                            if sources[0] in regtype and regtype[sources[0]] != "pointer":
                                reg_map[destination] = reg_map[src_reg]
                                if destination in regtype:
                                    regtype.pop(destination)
                            if sources[0] in regtype and regtype[sources[0]] == "pointer":
                                regtype[src_reg] = "interger"
                                param_types[reg_map[src_reg]] = "interger"
                                params[reg_map[src_reg]] = "interger"
                                regtype[reg_map[src_reg]] = "interger"
                                regtype[destination] = "pointer"
                                print(reg_map, regtype)
                                print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                                reg_var = reg_map[src_reg]
                                for mem in list(memory_map):
                                    if memory_map[mem] == reg_map[src_reg]:
                                        memory_map_type[mem] = regtype[src_reg]
                                        memory_map.pop(mem)
                                for reg in list(reg_map):
                                    if reg_map[reg]==reg_var:
                                        regtype[reg]=regtype[reg_var]
                                        reg_map.pop(reg)
                                if reg_map == {} and memory_map == {}:
                                    break
                            else:
                                print(reg_map, regtype)
                        # else:
                        #     continue
                    if destination in reg_map and cflag==0:
                        if all(src not in reg_map for src in sources):  # 仅追踪来源于当前参数的寄存器
                            print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                            print(f"[DEBUG] 记录寄存器映射: {destination} <- {sources}\n")
                            print(reg_map,regtype)
                            flow_info[reg_map[destination]].append({
                                "address": hex(addr),
                                "mnemonic": mnemonic,
                                "type": "reg_to_reg",
                                "destination": destination,
                                "sources": sources
                            })
                            #print("寄存器的值被修改了")
                            reg_map.pop(destination)
                            print(reg_map,regtype)
                        if sources[0] in reg_map and sources[1] in reg_map:
                            src_reg = sources[0]
                            print(reg_map,regtype)
                            print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                            print(f"[DEBUG] 记录寄存器映射: {destination} <- {sources}\n")
                            print("regtype:",regtype)
                            flow_info[reg_map[destination]].append({
                                "address": hex(addr),
                                "mnemonic": mnemonic,
                                "type": "reg_to_reg",
                                "destination": destination,
                                "sources": sources
                            })
                            if src_reg in regtype and regtype[src_reg]=="pointer":
                                regtype[sources[1]] = "interger"
                                regtype[reg_map[sources[1]]] = "interger"
                                param_types[reg_map[sources[1]]] = regtype[sources[1]]
                                params[reg_map[sources[1]]] = regtype[sources[1]]
                                print(f"[INFO] 参数 {reg_map[sources[1]]} 的传播链: {flow_info[reg_map[sources[1]]]}\n")
                                reg_var = reg_map[sources[1]]
                                for mem in list(memory_map):
                                    if memory_map[mem] == reg_map[sources[1]]:
                                        memory_map_type[mem] = regtype[sources[1]]
                                        memory_map.pop(mem)
                                for reg in list(reg_map):
                                    if reg_map[reg] == reg_var:
                                        regtype[reg]=regtype[reg_var]
                                        reg_map.pop(reg)
                                if reg_map == {} and memory_map == {}:
                                    break
                            if sources[1] in regtype and regtype[sources[1]] == "pointer":
                                regtype[src_reg] = "interger"
                                regtype[reg_map[src_reg]] = "interger"
                                param_types[reg_map[src_reg]] = "interger"
                                params[reg_map[src_reg]] = "interger"
                                regtype[destination] = "pointer"
                                reg_map[destination] = reg_map[sources[1]]
                                print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                                reg_var = reg_map[src_reg]
                                for mem in list(memory_map):
                                    if memory_map[mem] == reg_map[src_reg]:
                                        memory_map_type[mem] = regtype[src_reg]
                                        memory_map.pop(mem)
                                for reg in list(reg_map):
                                    if reg_map[reg] == reg_var:
                                        regtype[reg]=regtype[reg_var]
                                        reg_map.pop(reg)
                                if reg_map == {} and memory_map == {}:
                                    break
                            if sources[1] in regtype and regtype[sources[1]]!= "pointer":
                                reg_map[destination] = reg_map[sources[0]]
                                if destination in regtype:
                                    regtype.pop(destination)
                            if sources[0] in regtype and regtype[sources[0]]!= "pointer":
                                reg_map[destination] = reg_map[sources[1]]
                                if destination in regtype:
                                    regtype.pop(destination)
                            if sources[0] not in regtype and sources[1] not in regtype:
                                inte_reg[reg_map[sources[0]]] = reg_map[sources[1]]
                                inte_reg[reg_map[sources[1]]] = reg_map[sources[0]]
                                if destination not in sources:
                                    reg_map.pop(destination)
                                if destination in regtype:
                                    regtype.pop(destination)
                            print(reg_map,regtype)
                        if sources[0] in reg_map and sources[1] not in reg_map:
                            src_reg = sources[0]
                            print(reg_map,regtype)
                            print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                            print(f"[DEBUG] 记录寄存器映射: {destination} <- {src_reg}\n")
                            print("regtype:",regtype)
                            flow_info[reg_map[src_reg]].append({
                                "address": hex(addr),
                                "mnemonic": mnemonic,
                                "type": "reg_to_reg",
                                "destination": destination,
                                "sources": src_reg
                            })
                            print("既是源寄存器，也是目的寄存器")

                            if sources[1] in regtype and regtype[sources[1]]=="pointer":
                                regtype[sources[0]] = "interger"
                                param_types[reg_map[src_reg]] = "interger"
                                params[reg_map[src_reg]] = "interger"
                                regtype[destination] = "pointer"
                                regtype[reg_map[src_reg]] = "interger"
                                print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                                reg_var = reg_map[src_reg]
                                for mem in list(memory_map):
                                    if memory_map[mem] == reg_map[src_reg]:
                                        memory_map_type[mem] = regtype[src_reg]
                                        memory_map.pop(mem)
                                for reg in list(reg_map):
                                    if reg_map[reg]==reg_var:
                                        regtype[reg]=regtype[reg_var]
                                        reg_map.pop(reg)
                                if reg_map == {} and memory_map == {}:
                                    break
                            if sources[1] in regtype and regtype[sources[1]]!= "pointer":
                                reg_map[destination] = reg_map[sources[0]]

                            print(reg_map,regtype)

                        if sources[0] not in reg_map and sources[1] in reg_map:
                            src_reg=sources[1]
                            print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                            print(f"******++++[DEBUG] 记录寄存器映射*******: {destination} <- {src_reg}<-{reg_map[src_reg]}\n")
                            print(reg_map,regtype)
                            flow_info[reg_map[src_reg]].append({
                                "address": hex(addr),
                                "mnemonic": mnemonic,
                                "type": "reg_to_reg",
                                "destination": destination,
                                "sources": src_reg
                            })

                            if sources[0] in regtype and regtype[sources[0]]=="pointer":
                                param_types[reg_map[src_reg]] = "interger"
                                params[reg_map[src_reg]] = "interger"
                                regtype[src_reg]="interger"
                                regtype[reg_map[src_reg]] = "interger"
                                print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                                reg_var = reg_map[src_reg]
                                for mem in list(memory_map):
                                    if memory_map[mem] == reg_map[src_reg]:
                                        memory_map_type[mem] = regtype[src_reg]
                                        memory_map.pop(mem)
                                for reg in list(reg_map):
                                    if reg_map[reg]==reg_var:
                                        regtype[reg]=regtype[reg_var]
                                        reg_map.pop(reg)
                                if reg_map == {} and memory_map == {}:
                                    break
                            if sources[0] in regtype and regtype[sources[0]] != "pointer":
                                reg_map[destination] = reg_map[sources[1]]

        if mnemonic in {"arithmetic_sub"}:
            cflag=0
            if len(sources) ==1:
                print(hex(addr),reg_map)
                if destination in reg_map:#不传播
                    if sources[0] not in reg_map:
                        print(f"[DEBUG] 记录寄存器映射: {destination} <- {sources}\n")
                        print(reg_map,regtype)
                        flow_info[reg_map[destination]].append({
                            "address": hex(addr),
                            "mnemonic": mnemonic,
                            "type": "reg_to_reg",
                            "destination": destination,
                            "sources": sources[0]
                        })
                        print("参数参数数学运算，寄存器的值被修改了")
                        if sources[0] in regtype and regtype[sources[0]] == "pointer":
                            param_types[reg_map[destination]] = "pointer"
                            regtype[reg_map[destination]]="pointer"
                            params[reg_map[destination]] = "pointer"
                            regtype[destination] = "interger"
                            print(f"[INFO] 参数 {reg_map[destination]} 的传播链: {flow_info[reg_map[destination]]}\n")
                            reg_var = reg_map[destination]
                            for mem in list(memory_map):
                                if memory_map[mem] == reg_map[destination]:
                                    memory_map_type[mem] = regtype[destination]
                                    memory_map.pop(mem)
                            for reg in list(reg_map):
                                if reg_map[reg]==reg_var:
                                    regtype[reg]=regtype[reg_var]
                                    reg_map.pop(reg)
                            if reg_map == {} and memory_map == {}:
                                break
                    if sources[0] in reg_map:
                        print(f"**********[DEBUG] 记录寄存器映射**********: {destination} <- {sources}\n")
                        src_reg = sources[0]
                        print(reg_map,regtype)

                        #reg_map[destination] = reg_map[src_reg]
                        flow_info[reg_map[destination]].append({
                            "address": hex(addr),
                            "mnemonic": mnemonic,
                            "type": "reg_to_reg",
                            "destination": destination,
                            "sources": sources[0]
                        })
                        if destination in regtype:
                            print(regtype[destination])
                        #print("寄存器的值被修改了")
                        if sources[0] in regtype and regtype[sources[0]] == "pointer":
                            #param_types[reg_map[destination]] = "pointer"
                            param_types[reg_map[sources[0]]] = regtype[sources[0]]
                            params[reg_map[sources[0]]] = regtype[sources[0]]
                            regtype[reg_map[destination]] = "pointer"
                            regtype[destination]="interger"
                            print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                            reg_var = reg_map[src_reg]
                            for mem in list(memory_map):
                                if memory_map[mem] == reg_map[src_reg]:
                                    memory_map_type[mem] = regtype[src_reg]
                                    memory_map.pop(mem)
                            for reg in list(reg_map):
                                if reg_map[reg]==reg_var:
                                    regtype[reg]=regtype[reg_var]
                                    reg_map.pop(reg)
                            if reg_map == {} and memory_map == {}:
                                break
                if destination not in reg_map:#也不传递
                    if sources[0] in reg_map :  # 仅追踪来源于当前参数的寄存器,两个参数的情况
                        src_reg = sources[0]
                       # print(hex(addr), sources[0], reg_map[sources[0]])
                        #print(hex(addr),reg_map,regtype[destination])
                        print(reg_map,regtype)
                        print(f"[DEBUG] 记录寄存器映射: {destination} <- {reg_map[src_reg]}\n")
                        flow_info[reg_map[src_reg]].append({
                            "address": hex(addr),
                            "mnemonic": mnemonic,
                            "type": "reg_to_reg",
                            "destination": destination,
                            "sources": sources[0]
                        })
                        if destination in regtype and regtype[destination] == "interger":
                            print(regtype[destination])
                            param_types[reg_map[src_reg]] = "interger"
                            params[reg_map[src_reg]] = "interger"
                            regtype[src_reg]="interger"
                            regtype[reg_map[src_reg]]="interger"
                            print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                            reg_var = reg_map[src_reg]
                            for mem in list(memory_map):
                                if memory_map[mem] == reg_map[src_reg]:
                                    memory_map_type[mem] = regtype[src_reg]
                                    memory_map.pop(mem)
                            for reg in list(reg_map):
                                if reg_map[reg]==reg_var:
                                    regtype[reg]=regtype[reg_var]
                                    reg_map.pop(reg)
                            if reg_map == {} and memory_map == {}:
                                break

                        if sources[0] in regtype and regtype[sources[0]] == "pointer":
                            param_types[reg_map[sources[0]]] = "pointer"
                            params[reg_map[sources[0]]] = "pointer"
                            regtype[destination] = "pointer"
                            print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                            reg_var = reg_map[src_reg]
                            for mem in list(memory_map):
                                if memory_map[mem] == reg_map[src_reg]:
                                    memory_map_type[mem] = regtype[src_reg]
                                    memory_map.pop(mem)
                            for reg in list(reg_map):
                                if reg_map[reg]==reg_var:
                                    regtype[reg]=regtype[reg_var]
                                    reg_map.pop(reg)
                            if reg_map == {} and memory_map == {}:
                                break
            if len(sources) ==2:###????????算术运算的传播问题,参数类型
                print(reg_map)
                if destination not in reg_map:
                    if sources[0] in reg_map and sources[1] not in reg_map:
                        print(hex(addr),sources[0])
                        #print(regtype[sources[1]])
                        src_reg = sources[0]
                        #if destination not in sources:
                        cflag=1
                        print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                        print(f"[DEBUG] 记录寄存器映射: {destination} <- {reg_map[src_reg]}->{sources}\n")
                        flow_info[reg_map[src_reg]].append({
                            "address": hex(addr),
                            "mnemonic": mnemonic,
                            "type": "reg_to_reg",
                            "destination": destination,
                            "sources": sources
                        })
                        print(reg_map, regtype, memory_map)
                        if sources[1] in regtype and regtype[sources[1]] == "pointer":
                            regtype[sources[0]] = "pointer"
                            regtype[reg_map[sources[0]]]="pointer"
                            param_types[reg_map[sources[0]]] = "pointer"
                            params[reg_map[sources[0]]] = "pointer"
                            regtype[destination] = "interger"
                            print("*****************regtype:",regtype)
                            print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                           # print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                            reg_var = reg_map[src_reg]
                            for mem in list(memory_map):
                                if memory_map[mem] == reg_map[src_reg]:
                                    memory_map_type[mem] = regtype[src_reg]
                                    memory_map.pop(mem)
                            for reg in list(reg_map):
                                if reg_map[reg]==reg_var:
                                    regtype[reg]=regtype[reg_var]
                                    reg_map.pop(reg)
                            if reg_map == {} and memory_map == {}:
                                break
                        if sources[1] in regtype and regtype[sources[1]] != "pointer":
                            reg_map[destination] = reg_map[src_reg]
                            print(reg_map, regtype, memory_map)
                            if destination in regtype:
                                regtype.pop(destination)
                    if sources[1] in reg_map and sources[0] not in reg_map:
                        print(reg_map,regtype)
                        src_reg = sources[1]
                        cflag = 1
                        print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                        print(f"[DEBUG] 记录寄存器映射: {destination} <- {reg_map[src_reg]}->{sources}\n")
                        print(reg_map,regtype)
                        flow_info[reg_map[src_reg]].append({
                            "address": hex(addr),
                            "mnemonic": mnemonic,
                            "type": "reg_to_reg",
                            "destination": destination,
                            "sources": sources
                        })
                       # print(hex(addr),regtype[sources[0]])
                        if sources[0] in regtype and regtype[sources[0]] =="interger":
                            regtype[sources[1]] = "interger"
                            regtype[reg_map[sources[1]]] = "interger"
                            param_types[reg_map[sources[1]]] = "interger"
                            params[reg_map[sources[1]]] = "interger"
                            print(reg_map, regtype)
                            regtype[destination] = "interger"
                            print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                            reg_var = reg_map[src_reg]
                            for mem in list(memory_map):
                                if memory_map[mem] == reg_map[src_reg]:
                                    memory_map_type[mem] = regtype[src_reg]
                                    memory_map.pop(mem)
                            for reg in list(reg_map):
                                if reg_map[reg] == reg_var:
                                    regtype[reg] = regtype[reg_var]
                                    reg_map.pop(reg)
                            if reg_map == {} and memory_map == {}:
                                break

                        if sources[1] in regtype and regtype[sources[1]] != "pointer":
                            #reg_map[destination] = reg_map[sources[0]]
                            if destination in regtype:
                                regtype.pop(destination)

                        if sources[1] in regtype and regtype[sources[1]] == "pointer":
                            regtype[sources[1]] = "pointer"
                            regtype[reg_map[sources[1]]]="pointer"
                            param_types[reg_map[sources[1]]] = "pointer"
                            params[reg_map[sources[1]]] = "pointer"
                            print("regtype:", regtype)
                            regtype[destination] = "interger"
                            regtype[sources[0]]="pointer"
                            print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                            reg_var = reg_map[src_reg]
                            for mem in list(memory_map):
                                if memory_map[mem] == reg_map[src_reg]:
                                    memory_map_type[mem] = regtype[src_reg]
                                    memory_map.pop(mem)
                            for reg in list(reg_map):
                                if reg_map[reg]==reg_var:
                                    regtype[reg]=regtype[reg_var]
                                    reg_map.pop(reg)
                            if reg_map == {} and memory_map == {}:
                                break
                    if sources[0] in reg_map and sources[1] in reg_map:
                        src_reg = sources[0]
                        print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                        print(f"[DEBUG] 记录寄存器映射: {destination} <- {reg_map[src_reg]}->{sources}\n")
                        flow_info[reg_map[src_reg]].append({
                            "address": hex(addr),
                            "mnemonic": mnemonic,
                            "type": "reg_to_reg",
                            "destination": destination,
                            "sources": sources
                        })
                        print(reg_map, regtype, memory_map)
                        if sources[1] in regtype and regtype[sources[1]] == "pointer":
                            regtype[sources[0]] = "pointer"
                            regtype[reg_map[sources[0]]] = "pointer"
                            param_types[reg_map[sources[0]]] = "pointer"
                            params[reg_map[sources[0]]] = "pointer"
                            regtype[destination] = "interger"
                            print("*****************regtype:", regtype)
                            print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                            # print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                            reg_var = reg_map[src_reg]
                            for mem in list(memory_map):
                                if memory_map[mem] == reg_map[src_reg]:
                                    memory_map_type[mem] = regtype[src_reg]
                                    memory_map.pop(mem)
                            for reg in list(reg_map):
                                if reg_map[reg] == reg_var:
                                    regtype[reg] = regtype[reg_var]
                                    reg_map.pop(reg)
                            if reg_map == {} and memory_map == {}:
                                break
                        if sources[1] in regtype and regtype[sources[1]] != "pointer":
                            reg_map[destination] = reg_map[src_reg]
                            print(reg_map, regtype, memory_map)
                            if destination in regtype:
                                regtype.pop(destination)

                        if sources[0] in regtype and regtype[source[0]] == "interger":
                            regtype[sources[1]] = "interger"
                            regtype[reg_map[sources[1]]] = "interger"
                            param_types[reg_map[sources[1]]] = "interger"
                            params[reg_map[sources[1]]] = "interger"
                            print(reg_map, regtype)
                            regtype[destination] = "interger"
                            print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                            reg_var = reg_map[src_reg]
                            for mem in list(memory_map):
                                if memory_map[mem] == reg_map[src_reg]:
                                    memory_map_type[mem] = regtype[src_reg]
                                    memory_map.pop(mem)
                            for reg in list(reg_map):
                                if reg_map[reg] == reg_var:
                                    regtype[reg] = regtype[reg_var]
                                    reg_map.pop(reg)
                            if reg_map == {} and memory_map == {}:
                                break
                        if sources[0] not in regtype and sources[1] not in regtype:
                            print(sources)
                            # sub_inte_reg[reg_map[sources[0]]] = reg_map[sources[1]]
                            # sub_inte_reg[reg_map[sources[1]]] = reg_map[sources[0]]

                            sub_inte_reg['s'+sources[0]] = reg_map[sources[1]]
                            sub_inte_reg['d'+sources[1]] = reg_map[sources[0]]


                    # else:
                    #     continue
                if destination in reg_map and cflag==0:
                    if all(src not in reg_map for src in sources):  # 仅追踪来源于当前参数的寄存器
                        print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                        print(f"[DEBUG] 记录寄存器映射: {destination} <- {sources}\n")
                        print(reg_map,regtype)
                        flow_info[reg_map[destination]].append({
                            "address": hex(addr),
                            "mnemonic": mnemonic,
                            "type": "reg_to_reg",
                            "destination": destination,
                            "sources": sources
                        })
                        #print("寄存器的值被修改了")
                        reg_map.pop(destination)
                        print(reg_map,regtype)
                    if sources[0] in reg_map and sources[1] in reg_map:  # 仅追踪来源于当前参数的寄存器
                        src_reg = sources[0]
                        print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                        print(f"[DEBUG] 记录寄存器映射: {destination} <- {sources}\n")
                        print(reg_map,regtype)
                        flow_info[reg_map[destination]].append({
                            "address": hex(addr),
                            "mnemonic": mnemonic,
                            "type": "reg_to_reg",
                            "destination": destination,
                            "sources": sources
                        })
                        if sources[1] in regtype and regtype[sources[1]]=="pointer":
                            regtype[sources[0]] = "pointer"
                            regtype[reg_map[sources[0]]] = "pointer"
                            param_types[reg_map[sources[0]]] = "pointer"
                            params[reg_map[sources[0]]] = "pointer"
                            regtype[destination] = "interger"

                            #print(f"[INFO] 参数 {reg_map[sources[0]]} 的传播链: {flow_info[reg_map[sources[0]]]}\n")
                            print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                            reg_var = reg_map[src_reg]
                            for mem in list(memory_map):
                                if memory_map[mem] == reg_map[src_reg]:
                                    memory_map_type[mem] = regtype[src_reg]
                                    memory_map.pop(mem)
                            for reg in list(reg_map):
                                if reg_map[reg]==reg_var:
                                    regtype[reg]=regtype[reg_var]
                                    reg_map.pop(reg)
                            if reg_map == {} and memory_map == {}:
                                break
                        if sources[0] in regtype and regtype[sources[0]] != "pointer":
                            reg_map[destination] = reg_map[src_reg]
                        #print("寄存器的值被修改了")
                        reg_map.pop(destination)
                        print(reg_map,regtype)
                    if sources[0] in reg_map and sources[1] not in reg_map:
                        src_reg = sources[0]
                        print(reg_map,regtype)
                        print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                        print(f"[DEBUG] 记录寄存器映射: {destination} <- {src_reg}\n")
                        print("regtype:",regtype)
                        flow_info[reg_map[src_reg]].append({
                            "address": hex(addr),
                            "mnemonic": mnemonic,
                            "type": "reg_to_reg",
                            "destination": destination,
                            "sources": src_reg
                        })
                        print("既是源寄存器，也是目的寄存器")

                        if sources[1] in regtype and regtype[sources[1]]=="pointer":
                            regtype[sources[0]] = "pointer"
                            regtype[reg_map[sources[0]]] = "pointer"
                            param_types[reg_map[sources[0]]] = "pointer"
                            params[reg_map[sources[0]]] = "pointer"
                            regtype[destination] = "interger"
                            print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                            reg_var = reg_map[src_reg]
                            for mem in list(memory_map):
                                if memory_map[mem] == reg_map[src_reg]:
                                    memory_map_type[mem] = regtype[src_reg]
                                    memory_map.pop(mem)
                            for reg in list(reg_map):
                                if reg_map[reg]==reg_var:
                                    regtype[reg]=regtype[reg_var]
                                    reg_map.pop(reg)
                            if reg_map == {} and memory_map == {}:
                                break
                        print("regtype:", regtype)
                        #reg_map.pop(destination)
                            #reg_map.pop(destination)
                    if sources[0] not in reg_map and sources[1] in reg_map:
                        src_reg=sources[1]
                        print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                        print(f"[DEBUG] 记录寄存器映射*******: {destination} <- {sources}\n")
                        print("regtype:",regtype)
                        flow_info[reg_map[destination]].append({
                            "address": hex(addr),
                            "mnemonic": mnemonic,
                            "type": "reg_to_reg",
                            "destination": destination,
                            "sources": sources
                        })
                        print("寄存器的值被修改了")
                        #param_types[reg_map[destination]] = "maybe interger"

                        if sources[1] in regtype and regtype[sources[1]]=="pointer":
                            regtype[sources[1]] = "pointer"
                            regtype[reg_map[sources[1]]] = "pointer"
                            param_types[reg_map[sources[1]]] = "pointer"
                            params[reg_map[sources[1]]] = "pointer"
                            regtype[destination] = "interger"
                            print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                            reg_var = reg_map[src_reg]
                            for mem in list(memory_map):
                                if memory_map[mem] == reg_map[src_reg]:
                                    memory_map_type[mem] = regtype[src_reg]
                                    memory_map.pop(mem)
                            for reg in list(reg_map):
                                if reg_map[reg]==reg_var:
                                    regtype[reg]=regtype[reg_var]
                                    reg_map.pop(reg)
                            if reg_map == {} and memory_map == {}:
                                break
                        print("regtype:", regtype)

        if mnemonic in {"shift_r"}:
            cflag=0
            if imm != None:
                if len(sources) == 1:

                    if destination in reg_map:
                        print(f"[DEBUG] 记录寄存器映射: {destination} <- {sources}\n")
                        print(reg_map,regtype,memory_map,memory_map_type)
                        flow_info[reg_map[destination]].append({
                            "address": hex(addr),
                            "mnemonic": mnemonic,
                            "type": "reg_to_reg",
                            "destination": destination,
                            "sources": sources[0]
                        })
                        print("参数参数数学运算，寄存器的值被修改了")
                        regtype[destination]="interger"
                        param_types[reg_map[destination]] = "interger"
                        params[reg_map[destination]] = "interger"
                        regtype[reg_map[destination]]="interger"

                        print(reg_map, regtype, memory_map, memory_map_type)
                        print(f"[INFO] 参数 {reg_map[destination]} 的传播链: {flow_info[reg_map[destination]]}\n")
                        reg_var = reg_map[destination]
                        for mem in list(memory_map):
                            if memory_map[mem] == reg_map[destination]:
                                memory_map_type[mem] = regtype[destination]
                                memory_map.pop(mem)

                        for reg in list(reg_map):
                            if reg_map[reg]==reg_var:
                                regtype[reg]=regtype[reg_var]
                                reg_map.pop(reg)
                        if reg_map == {} and memory_map == {}:
                            break
                    if destination not in reg_map:
                        regtype[destination]="interger"

                if len(sources) == 2:  ###????????算术运算的传播问题,存在立即数
                    if sources[0] not in reg_map:  # 仅追踪来源于当前参数的寄存器
                        src_reg = sources[0]
                        print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                        print(f"[DEBUG] 记录寄存器映射: {destination} <- {sources}\n")
                        print(reg_map, regtype)
                        regtype[destination] = "interger"
                        regtype[src_reg] = "interger"
                        if destination in reg_map:
                            flow_info[reg_map[destination]].append({
                                "address": hex(addr),
                                "mnemonic": mnemonic,
                                "type": "reg_to_reg",
                                "destination": destination,
                                "sources": sources
                            })
                            reg_map.pop(destination)
                            print(reg_map, regtype)
                    if sources[0] in reg_map:  # 仅追踪来源于当前参数的寄存器
                        src_reg = sources[0]
                        print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                        print(f"[DEBUG] 记录寄存器映射: {destination} <- {sources}\n")
                        print(reg_map, regtype)
                        reg_map[destination] = reg_map[src_reg]
                        flow_info[reg_map[src_reg]].append({
                            "address": hex(addr),
                            "mnemonic": mnemonic,
                            "type": "reg_to_reg",
                            "destination": destination,
                            "sources": sources
                        })
                        # print("寄存器的值被修改了")
                        regtype[src_reg] = "interger"
                        regtype[reg_map[src_reg]] = "interger"
                        print(reg_map, regtype)
                        param_types[reg_map[src_reg]] = "interger"
                        params[reg_map[src_reg]] = "interger"

                        print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                        reg_var = reg_map[src_reg]
                        for mem in list(memory_map):
                            if memory_map[mem] == reg_map[src_reg]:
                                memory_map_type[mem] = regtype[src_reg]
                                memory_map.pop(mem)
                        for reg in list(reg_map):
                            if reg_map[reg] == reg_var:
                                regtype[reg] = regtype[reg_var]
                                reg_map.pop(reg)
                        regtype[destination] = "interger"
                        if reg_map == {} and memory_map == {}:
                            break
            if imm==None:
                if len(sources) ==1:
                    print(hex(addr),reg_map)
                    if sources[0] not in reg_map:
                        regtype[sources[0]] = "interger"
                        regtype[destination] = "interger"
                        if destination in reg_map:
                            print(f"[DEBUG] 记录寄存器映射: {destination} <- {sources}\n")
                            print(reg_map,regtype)
                            flow_info[reg_map[destination]].append({
                                "address": hex(addr),
                                "mnemonic": mnemonic,
                                "type": "reg_to_reg",
                                "destination": destination,
                                "sources": sources[0]
                            })
                            print("参数参数数学运算，寄存器的值被修改了")

                            regtype[reg_map[destination]]="interger"
                            param_types[reg_map[destination]]="interger"
                            params[reg_map[destination]] = "interger"
                            print(reg_map, regtype)
                            print(f"[INFO] 参数 {reg_map[destination]} 的传播链: {flow_info[reg_map[destination]]}\n")
                            reg_var = reg_map[destination]
                            for mem in list(memory_map):
                                if memory_map[mem] == reg_map[destination]:
                                    memory_map_type[mem] = regtype[destination]
                                    memory_map.pop(mem)
                            for reg in list(reg_map):
                                if reg_map[reg]==reg_var:
                                    regtype[reg]=regtype[reg_var]
                                    reg_map.pop(reg)
                            if reg_map == {} and memory_map == {}:
                                break
                    if sources[0] in reg_map:
                        print(f"**********[DEBUG] 记录寄存器映射**********: {destination} <- {sources}\n")
                        src_reg = sources[0]
                        print(reg_map, regtype)

                        #reg_map[destination] = reg_map[src_reg]
                        flow_info[reg_map[sources[0]]].append({
                            "address": hex(addr),
                            "mnemonic": mnemonic,
                            "type": "reg_to_reg",
                            "destination": destination,
                            "sources": sources[0]
                        })
                        regtype[src_reg] = "interger"
                        regtype[reg_map[src_reg]] = "interger"
                        param_types[reg_map[src_reg]] = "interger"
                        params[reg_map[src_reg]] = "interger"
                        regtype[destination] = "interger"
                        #param_types[reg_map[destination]] = "interger"
                        print(reg_map,regtype)
                        print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                        reg_var = reg_map[src_reg]
                        #print("寄存器的值被修改了")
                        if destination in reg_map:
                            print(f"[DEBUG] 记录寄存器映射: {destination} <- {sources}\n")
                            print(reg_map,regtype)
                            flow_info[reg_map[destination]].append({
                                "address": hex(addr),
                                "mnemonic": mnemonic,
                                "type": "reg_to_reg",
                                "destination": destination,
                                "sources": sources[0]
                            })
                            print("参数参数数学运算，寄存器的值被修改了")

                            regtype[reg_map[destination]]="interger"
                            param_types[reg_map[destination]]="interger"
                            params[reg_map[destination]] = "interger"
                            print(reg_map, regtype)
                            print(f"[INFO] 参数 {reg_map[destination]} 的传播链: {flow_info[reg_map[destination]]}\n")
                            reg_var2 = reg_map[destination]
                            for mem in list(memory_map):
                                if memory_map[mem] == reg_map[destination]:
                                    memory_map_type[mem] = regtype[destination]
                                    memory_map.pop(mem)
                            for reg in list(reg_map):
                                if reg_map[reg]==reg_var2:
                                    regtype[reg]=regtype[reg_var2]
                                    reg_map.pop(reg)
                            if reg_map == {} and memory_map == {}:
                                break

                        for mem in list(memory_map):
                            if memory_map[mem] == reg_map[src_reg]:
                                memory_map_type[mem] = regtype[src_reg]
                                memory_map.pop(mem)
                        for reg in list(reg_map):
                            if reg_map[reg]==reg_var:
                                regtype[reg]=regtype[reg_var]
                                reg_map.pop(reg)
                        if reg_map == {} and memory_map == {}:
                            break

                if len(sources) ==2:###????????算术运算的传播问题,参数类型
                    if destination not in reg_map:
                        cflag = 1
                        if sources[0] in reg_map:
                            src_reg = sources[0]
                            print(reg_map,regtype)
                            print(hex(addr),sources[0])
                            #print(regtype[sources[1]])
                            #if destination not in sources:
                            print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                            print(f"[DEBUG] 记录寄存器映射: {destination} <- {reg_map[src_reg]}->{sources}\n")
                            reg_map[destination] = reg_map[src_reg]
                            flow_info[reg_map[src_reg]].append({
                                "address": hex(addr),
                                "mnemonic": mnemonic,
                                "type": "reg_to_reg",
                                "destination": destination,
                                "sources": sources
                            })
                            regtype[sources[1]] = "interger"
                            src_reg=sources[0]
                            regtype[sources[0]]="interger"
                            regtype[reg_map[sources[0]]] = "interger"
                            param_types[reg_map[sources[0]]] = "interger"
                            params[reg_map[sources[0]]] = "interger"
                            regtype[destination] = "interger"
                            print(reg_map,regtype)
                            print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                            reg_var = reg_map[src_reg]
                            if sources[1] in reg_map:
                                src_reg = sources[1]
                                regtype[reg_map[sources[1]]] = "interger"
                                param_types[reg_map[sources[1]]] = "interger"
                                params[reg_map[sources[1]]] = "interger"
                                print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                                reg_var2 = reg_map[src_reg]
                                for mem in list(memory_map):
                                    if memory_map[mem] == reg_map[src_reg]:
                                        memory_map_type[mem] = regtype[src_reg]
                                        memory_map.pop(mem)
                                for reg in list(reg_map):
                                    if reg_map[reg] == reg_var2:
                                        regtype[reg] = regtype[reg_var2]
                                        reg_map.pop(reg)
                                if reg_map == {} and memory_map == {}:
                                    break

                            for mem in list(memory_map):
                                if memory_map[mem] == reg_map[src_reg]:
                                    memory_map_type[mem] = regtype[src_reg]
                                    memory_map.pop(mem)
                            for reg in list(reg_map):
                                if reg_map[reg]==reg_var:
                                    regtype[reg]=regtype[reg_var]
                                    reg_map.pop(reg)
                            if reg_map == {} and memory_map == {}:
                                break

                        if sources[0] not in reg_map:
                            print(reg_map,regtype)
                            src_reg = sources[0]
                            regtype[sources[1]] = "interger"
                            if sources[1] in reg_map:
                                src_reg = sources[1]
                                regtype[reg_map[sources[1]]] = "interger"
                                param_types[reg_map[sources[1]]] = "interger"
                                params[reg_map[sources[1]]] = "interger"
                                print(f"[INFO] 参数 {reg_map[sources[1]]} 的传播链: {flow_info[reg_map[sources[1]]]}\n")
                                reg_var = reg_map[sources[1]]
                                for mem in list(memory_map):
                                    if memory_map[mem] == reg_map[src_reg]:
                                        memory_map_type[mem] = regtype[src_reg]
                                        memory_map.pop(mem)
                                for reg in list(reg_map):
                                    if reg_map[reg]==reg_var:
                                        regtype[reg]=regtype[reg_var]
                                        reg_map.pop(reg)
                                if reg_map == {} and memory_map == {}:
                                    break
                            regtype[sources[0]]="interger"
                            regtype[destination] = "interger"
                            print(reg_map,regtype)
                    if destination in reg_map and cflag==0:
                        if sources[0] not in reg_map:  # 仅追踪来源于当前参数的寄存器
                            src_reg=sources[0]
                            print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                            print(f"[DEBUG] 记录寄存器映射: {destination} <- {sources}\n")
                            print(reg_map,regtype)
                            flow_info[reg_map[destination]].append({
                                "address": hex(addr),
                                "mnemonic": mnemonic,
                                "type": "reg_to_reg",
                                "destination": destination,
                                "sources": sources
                            })
                            regtype[sources[1]] = "interger"
                            if sources[1] in reg_map:
                                src_reg=sources[1]
                                regtype[reg_map[sources[1]]] = "interger"
                                param_types[reg_map[sources[1]]]="interger"
                                params[reg_map[sources[1]]] = "interger"
                                reg_var = reg_map[sources[1]]
                                print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                                reg_var = reg_map[src_reg]
                                for mem in list(memory_map):
                                    if memory_map[mem] == reg_map[src_reg]:
                                        memory_map_type[mem] = regtype[src_reg]
                                        memory_map.pop(mem)
                                for reg in list(reg_map):
                                    if reg_map[reg]==reg_var:
                                        regtype[reg]=regtype[reg_var]
                                        reg_map.pop(reg)
                                if reg_map == {} and memory_map == {}:
                                    break
                            #regtype[reg_map[sources[0]]] = "interger"
                            #param_types[reg_map[destination]] = "interger"
                            regtype[destination] = "interger"
                            regtype[sources[0]]="interger"
                            if destination in reg_map:
                                reg_map.pop(destination)
                            print(reg_map,regtype)
                            #break
                        if sources[0] in reg_map:
                            src_reg = sources[0]
                            print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                            print(f"[DEBUG] 记录寄存器映射: {destination} <- {src_reg}\n")
                            print(reg_map,regtype)
                            flow_info[reg_map[destination]].append({
                                "address": hex(addr),
                                "mnemonic": mnemonic,
                                "type": "reg_to_reg",
                                "destination": destination,
                                "sources": src_reg
                            })
                            regtype[sources[1]] = "interger"

                            regtype[reg_map[sources[0]]] = "interger"
                            param_types[reg_map[src_reg]] = "interger"
                            params[reg_map[src_reg]] = "interger"
                            regtype[destination] = "interger"
                            regtype[src_reg] = "interger"
                            print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                            reg_var = reg_map[src_reg]

                            if sources[1] in reg_map:
                                src_reg=sources[1]
                                regtype[reg_map[sources[1]]] = "interger"
                                param_types[reg_map[sources[1]]] = "interger"
                                params[reg_map[sources[1]]] = "interger"
                                print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                                reg_var2 = reg_map[src_reg]
                                for mem in list(memory_map):
                                    if memory_map[mem] == reg_map[src_reg]:
                                        memory_map_type[mem] = regtype[src_reg]
                                        memory_map.pop(mem)
                                for reg in list(reg_map):
                                    if reg_map[reg]==reg_var2:
                                        regtype[reg]=regtype[reg_var2]
                                        reg_map.pop(reg)
                                if reg_map == {} and memory_map == {}:
                                    break
                            for mem in list(memory_map):
                                if memory_map[mem] == reg_map[src_reg]:
                                    memory_map_type[mem] = regtype[src_reg]
                                    memory_map.pop(mem)
                            for reg in list(reg_map):
                                if reg_map[reg]==reg_var:
                                    regtype[reg]=regtype[reg_var]
                                    reg_map.pop(reg)
                            if reg_map == {} and memory_map == {}:
                                break

        if mnemonic in {"logic"}:
            print(reg_map)
            print(hex(addr),mnemonic,len(sources),sources[0],destination)
            if len(sources) ==1:
                if imm != None:
                    if destination in reg_map:
                        print(reg_map,regtype)
                        print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                        print(f"[DEBUG] 记录寄存器映射: {destination} <- {sources}\n")
                        flow_info[reg_map[destination]].append({
                            "address": hex(addr),
                            "mnemonic": mnemonic,
                            "type": "reg_to_reg",
                            "destination": destination,
                            "sources": sources[0]
                        })
                        print("参数参数数学运算，寄存器的值被修改了")
                        regtype[destination]="interger"
                        # if destination in regtype:
                        #     param_types[reg_map[destination]] = regtype[destination]
                        #     params[reg_map[destination]] = regtype[destination]
                        #     print(reg_map, regtype)
                        #     for mem in list(memory_map):
                        #         if memory_map[mem] == reg_map[destination]:
                        #             memory_map_type[mem] = regtype[destination]
                        #             memory_map.pop(mem)
                        #     if reg_map[destination] in reg_map:
                        #         reg_map.pop(reg_map[destination])
                        #     if destination in reg_map:
                        #         reg_map.pop(destination)
                        #     if reg_map == {} and memory_map == {}:
                        #         break
                        reg_map.pop(destination)
                    if destination not in reg_map:
                        regtype[destination] = "interger"
                if imm == None:
                    if destination in reg_map:
                        if sources[0] not in reg_map:
                            print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                            print(f"[DEBUG] 记录寄存器映射: {destination} <- {sources}\n")
                            flow_info[reg_map[destination]].append({
                                "address": hex(addr),
                                "mnemonic": mnemonic,
                                "type": "reg_to_reg",
                                "destination": destination,
                                "sources": sources[0]
                            })
                            print("参数参数数学运算，寄存器的值被修改了")
                            param_types[reg_map[destination]] = "interger"
                            params[reg_map[destination]] = "interger"
                            regtype[destination] = "interger"
                            regtype[sources[0]]="interger"
                        if sources[0] in reg_map:
                            print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                            print(f"[DEBUG] 记录寄存器映射: {destination} <- {sources}\n")
                            src_reg = sources[0]
                            # reg_map[destination] = reg_map[src_reg]
                            flow_info[reg_map[destination]].append({
                                "address": hex(addr),
                                "mnemonic": mnemonic,
                                "type": "reg_to_reg",
                                "destination": destination,
                                "sources": sources[0]
                            })
                            # print("寄存器的值被修改了")
                            param_types[reg_map[destination]] = "interger"
                            params[reg_map[destination]] = "interger"
                    if destination not in reg_map:
                        if sources[0] in reg_map:  # 数据不传递
                            src_reg = sources[0]
                            # print(hex(addr), sources[0], reg_map[sources[0]])
                            # reg_map[destination] = reg_map[src_reg]
                            print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                            print(f"[DEBUG] 记录寄存器映射: {destination} <- {reg_map[src_reg]}\n")
                            flow_info[reg_map[src_reg]].append({
                                "address": hex(addr),
                                "mnemonic": mnemonic,
                                "type": "reg_to_reg",
                                "destination": destination,
                                "sources": sources[0]
                            })
                            # print("参数可能是整型")
                            if src_reg in regtype:
                                param_types[reg_map[src_reg]] = regtype[src_reg]
                                params[reg_map[src_reg]] = regtype[src_reg]
            if len(sources) ==2:
                if imm!=None:#包含立即数的指令
                    if destination in reg_map:
                        if sources[0] not in reg_map:  # 仅追踪来源于当前参数的寄存器，参数不传递
                            print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                            print(f"[DEBUG] 记录寄存器映射: {destination} <- {sources}\n")
                            flow_info[reg_map[destination]].append({
                                "address": hex(addr),
                                "mnemonic": mnemonic,
                                "type": "reg_to_reg",
                                "destination": destination,
                                "sources": sources
                            })
                            #print("寄存器的值被修改了")
#                             param_types[reg_map[destination]] = "interger"
#                             params[reg_map[destination]] = "interger"
                            regtype[destination]="interger"
                            reg_map.pop(destination)
                        if sources[0] in reg_map:
                            src_reg = sources[0]
                            print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                            print(f"[DEBUG] 记录寄存器映射: {destination} <- {src_reg}\n")
                            flow_info[reg_map[destination]].append({
                                "address": hex(addr),
                                "mnemonic": mnemonic,
                                "type": "reg_to_reg",
                                "destination": destination,
                                "sources": src_reg
                            })
                            print("寄存器的值被修改了")
#                             param_types[reg_map[destination]] = "interger"
#                             params[reg_map[destination]] = "interger"
#                             regtype[sources[0]]="interger"
                            regtype[destination]="interger"
                            reg_map.pop(destination)

                    if destination not in reg_map:
                        if sources[0] in reg_map:
                            src_reg = sources[0]
                            #reg_map[destination] = reg_map[src_reg]#v0直接被覆盖掉了，其实跟源操作数没关系
                            print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                            print(f"[DEBUG] 记录寄存器映射: {destination}<--{sources}\n")
                            flow_info[reg_map[src_reg]].append({
                                "address": hex(addr),
                                "mnemonic": mnemonic,
                                "type": "reg_to_reg",
                                "destination": destination,
                                "sources": sources
                            })
                            if src_reg in regtype:
                                param_types[reg_map[src_reg]] = regtype[src_reg]
                                params[reg_map[src_reg]] = regtype[src_reg]
                            regtype[destination] = "interger"
                        if sources[0] not in reg_map:
                            regtype[destination] = "interger"
                if imm==None:
                    if destination in reg_map:
                        if all(src not in reg_map for src in sources):  # 仅追踪来源于当前参数的寄存器，参数不传递
                            print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                            print(f"[DEBUG] 记录寄存器映射: {destination} <- {sources}\n")
                            flow_info[reg_map[destination]].append({
                                "address": hex(addr),
                                "mnemonic": mnemonic,
                                "type": "reg_to_reg",
                                "destination": destination,
                                "sources": sources
                            })
                            regtype[destination]="interger"
                            reg_map.pop(destination)
                            #print("寄存器的值被修改了")
                            # param_types[reg_map[destination]] = "interger"
                            # params[reg_map[destination]] = "interger"
                            # regtype[sources[0]]="interger"
                            # regtype[sources[1]]="interger"
                            # reg_map.pop(destination)
                        if all(src in reg_map for src in sources):  # 仅追踪来源于当前参数的寄存器，参数不传递
                            print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                            print(f"[DEBUG] 记录寄存器映射: {destination} <- {sources}\n")
                            flow_info[reg_map[destination]].append({
                                "address": hex(addr),
                                "mnemonic": mnemonic,
                                "type": "reg_to_reg",
                                "destination": destination,
                                "sources": sources
                            })
                            #print("寄存器的值被修改了")
                            param_types[reg_map[destination]] = "interger"
                            params[reg_map[destination]] = "interger"
                            regtype[sources[0]]="interger"
                            regtype[sources[1]]="interger"
                            #reg_map.pop(destination)
                        if sources[0] in reg_map:
                            src_reg = sources[0]
                            print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                            print(f"[DEBUG] 记录寄存器映射: {destination} <- {src_reg}\n")
                            flow_info[reg_map[destination]].append({
                                "address": hex(addr),
                                "mnemonic": mnemonic,
                                "type": "reg_to_reg",
                                "destination": destination,
                                "sources": src_reg
                            })
                            print("寄存器的值被修改了")
                            param_types[reg_map[destination]] = "maybe interger"
                            params[reg_map[destination]] = "maybe interger"
                            if sources[1] in regtype and regtype[sources[1]] == "pointer":
                                reg_map.pop(destination)

                        if sources[1] in reg_map:
                            src_reg = sources[1]
                            print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                            print(f"[DEBUG] 记录寄存器映射: {destination} <- {src_reg}\n")
                            flow_info[reg_map[destination]].append({
                                "address": hex(addr),
                                "mnemonic": mnemonic,
                                "type": "reg_to_reg",
                                "destination": destination,
                                "sources": src_reg
                            })
                            print("寄存器的值被修改了")
                            param_types[reg_map[destination]] = "maybe interger"
                            params[reg_map[destination]] = "maybe interger"
                            if sources[0] in regtype and regtype[sources[0]] == "pointer":
                                reg_map.pop(destination)
                        #reg_map.pop(destination)
                        #reg_map.pop(destination)
                    if destination not in reg_map:#or      $v0, $a3, $v0
                        if all(src in reg_map for src in sources):
                            src_reg = sources[0]
                            #reg_map[destination] = reg_map[src_reg]
                            print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                            print(f"[DEBUG] 记录寄存器映射: {destination}---{sources}\n")
                            flow_info[reg_map[src_reg]].append({
                                "address": hex(addr),
                                "mnemonic": mnemonic,
                                "type": "reg_to_reg",
                                "destination": destination,
                                "sources": sources
                            })
                            # print("参数可能是整型")
                            # param_types[reg_map[src_reg]] = "interger"
                            # params[reg_map[src_reg]] = "interger"
                            # regtype[sources[0]]="interger"
                            # regtype[sources[1]]="interger"

                        elif sources[0] in reg_map and destination==sources[1]:
                            src_reg = sources[0]
                            if sources[1] in regtype and regtype[ sources[1]]!="pointer":
                                reg_map[destination] = reg_map[src_reg]
                            print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                            print(f"[DEBUG] 记录寄存器映射: {destination}---{sources}\n")
                            flow_info[reg_map[src_reg]].append({
                                "address": hex(addr),
                                "mnemonic": mnemonic,
                                "type": "reg_to_reg",
                                "destination": destination,
                                "sources": sources
                            })
                           # print("参数可能是整型")
                            param_types[reg_map[src_reg]] = "interger"
                            params[reg_map[src_reg]] = "interger"
                        elif sources[0] in reg_map and destination!=sources[1]:
                            print(reg_map,regtype)
                            src_reg = sources[0]
                            #reg_map[destination] = reg_map[src_reg]
                            print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                            print(f"[DEBUG] 记录寄存器映射: {destination}---{sources}\n")
                            flow_info[reg_map[src_reg]].append({
                                "address": hex(addr),
                                "mnemonic": mnemonic,
                                "type": "reg_to_reg",
                                "destination": destination,
                                "sources": sources
                            })
                           # print("参数可能是整型")
#                                 param_types[reg_map[src_reg]] = "interger"
#                                 params[reg_map[src_reg]] = "interger"
                        elif sources[1] in reg_map and destination==sources[0]:
                            src_reg = sources[1]
                            #reg_map[destination] = reg_map[src_reg]
                            print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                            print(f"[DEBUG] 记录寄存器映射: {destination}---{sources}\n")
                            flow_info[reg_map[src_reg]].append({
                                "address": hex(addr),
                                "mnemonic": mnemonic,
                                "type": "reg_to_reg",
                                "destination": destination,
                                "sources": sources
                            })
                           # print("参数可能是整型")
                            param_types[reg_map[src_reg]] = "interger"
                            params[reg_map[src_reg]] = "interger"
                        elif sources[1] in reg_map and destination != sources[0]:
                            src_reg = sources[1]
                            #reg_map[destination] = reg_map[src_reg]
                            print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                            print(f"[DEBUG] 记录寄存器映射: {destination}---{sources}\n")
                            flow_info[reg_map[src_reg]].append({
                                "address": hex(addr),
                                "mnemonic": mnemonic,
                                "type": "reg_to_reg",
                                "destination": destination,
                                "sources": sources
                            })
                            # print("参数可能是整型")

        if mnemonic in {"branch_conditional_zero"}:
            print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
            print(reg_map,regtype)
            if sources[0] in reg_map:
                src_reg = sources[0]
                print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                print(f"[DEBUG] 记录寄存器映射: {destination} <- {destination}\n")
                flow_info[reg_map[src_reg]].append({
                    "address": hex(addr),
                    "mnemonic": mnemonic,
                    "type": "reg_to_reg",
                    "destination": destination,
                    "sources": src_reg
                })
                if src_reg in regtype:
                    regtype[reg_map[src_reg]] = regtype[src_reg]
                    param_types[reg_map[src_reg]] = regtype[src_reg]
                    params[reg_map[src_reg]] = regtype[src_reg]

                    reg_var = reg_map[src_reg]
                    for mem in list(memory_map):
                        if memory_map[mem] == reg_map[src_reg]:
                            memory_map_type[mem] = regtype[src_reg]
                            memory_map.pop(mem)
                    for reg in list(reg_map):
                        if reg_map[reg] == reg_var:
                            regtype[reg] = regtype[reg_var]
                            reg_map.pop(reg)
                    if reg_map == {} and memory_map == {}:
                        break
                print(reg_map,regtype)

        if mnemonic in {"branch_conditional_lzero"}:
            print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
            print(reg_map,regtype)
            if sources[0] in reg_map:
                src_reg = sources[0]
                print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                print(f"[DEBUG] 记录寄存器映射: {destination} <- {destination}\n")
                flow_info[reg_map[src_reg]].append({
                    "address": hex(addr),
                    "mnemonic": mnemonic,
                    "type": "reg_to_reg",
                    "destination": destination,
                    "sources": src_reg
                })
                regtype[src_reg]="interger"
                regtype[reg_map[src_reg]]="interger"
                param_types[reg_map[src_reg]] = "interger"
                params[reg_map[src_reg]] = "interger"
                print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                reg_var=reg_map[src_reg]
                for mem in list(memory_map):
                    if memory_map[mem] == reg_map[src_reg]:
                        memory_map_type[mem] = regtype[src_reg]
                        memory_map.pop(mem)
                for reg in list(reg_map):
                    if reg_map[reg]==reg_var:
                        regtype[reg]=regtype[reg_var]
                        reg_map.pop(reg)
                if reg_map=={} and memory_map=={}:
                    break
                print(reg_map,regtype)
            if sources[0] not in reg_map:
                regtype[sources[0]]="interger"

        if mnemonic in {"branch_conditional"}:
            if sources[0] not in reg_map and sources[1] not in reg_map:
                print(sources[0], sources[1])
            if sources[0] in reg_map and sources[1] not in reg_map:
                src_reg = sources[0]
                print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                print(f"[DEBUG] 记录寄存器映射: {destination} <- {destination}\n")
                flow_info[reg_map[src_reg]].append({
                    "address": hex(addr),
                    "mnemonic": mnemonic,
                    "type": "reg_to_reg",
                    "destination": destination,
                    "sources": src_reg
                })
                if sources[1] in regtype and src_reg not in regtype:
                    regtype[src_reg] = regtype[sources[1]]
                    regtype[reg_map[src_reg]] = regtype[src_reg]
                    param_types[reg_map[src_reg]] = regtype[src_reg]
                    params[reg_map[src_reg]] = regtype[src_reg]
                    print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                    reg_var = reg_map[src_reg]
                    for mem in list(memory_map):
                        if memory_map[mem] == reg_map[src_reg]:
                            memory_map_type[mem] = regtype[src_reg]
                            memory_map.pop(mem)
                    for reg in list(reg_map):
                        if reg_map[reg]==reg_var:
                            regtype[reg]=regtype[reg_var]
                            reg_map.pop(reg)
                    if reg_map == {} and memory_map == {}:
                        break
                if sources[0] in regtype and sources[1] not in regtype:
                    src_reg = sources[0]
                    regtype[sources[1]] = regtype[src_reg]
                    param_types[reg_map[src_reg]] = regtype[src_reg]
                    params[reg_map[src_reg]] = regtype[src_reg]
                    print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                    reg_var = reg_map[src_reg]
                    for mem in list(memory_map):
                        if memory_map[mem] == reg_map[src_reg]:
                            memory_map_type[mem] = regtype[src_reg]
                            memory_map.pop(mem)
                    for reg in list(reg_map):
                        if reg_map[reg]==reg_var:
                            regtype[reg]=regtype[reg_var]
                            reg_map.pop(reg)
                    if reg_map == {} and memory_map == {}:
                        break
                if sources[0] not in regtype and sources[1] not in regtype:
                    print(sources[0], sources[1])
                    # 扩展接口
            if sources[0] not in reg_map and sources[1] in reg_map:
                src_reg = sources[1]
                print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                print(f"[DEBUG] 记录寄存器映射: {destination} <- {destination}\n")
                flow_info[reg_map[src_reg]].append({
                    "address": hex(addr),
                    "mnemonic": mnemonic,
                    "type": "reg_to_reg",
                    "destination": destination,
                    "sources": src_reg
                })
                print(reg_map,regtype)
                if sources[0] in regtype and sources[1] not in regtype:
                    regtype[src_reg] = regtype[sources[0]]
                    regtype[reg_map[src_reg]] = regtype[sources[0]]
                    param_types[reg_map[src_reg]] = regtype[src_reg]
                    params[reg_map[src_reg]] = regtype[src_reg]
                    print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                    reg_var = reg_map[src_reg]
                    print(reg_map, regtype)
                    for mem in list(memory_map):
                        if memory_map[mem] == reg_map[src_reg]:
                            memory_map_type[mem] = regtype[src_reg]
                            memory_map.pop(mem)
                    for reg in list(reg_map):
                        if reg_map[reg]==reg_var:
                            regtype[reg]=regtype[reg_var]
                            reg_map.pop(reg)
                    if reg_map == {} and memory_map == {}:
                        break
                if sources[0] not in regtype and sources[1] not in regtype:
                    print(sources[0], sources[1])

            if sources[0] in reg_map and sources[1] in reg_map:
                src_reg = sources[0]
                print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
                print(f"[DEBUG] 记录寄存器映射: {destination} <- {destination}\n")
                flow_info[reg_map[src_reg]].append({
                    "address": hex(addr),
                    "mnemonic": mnemonic,
                    "type": "reg_to_reg",
                    "destination": destination,
                    "sources": src_reg
                })
                # param_types[reg_map[src_reg]] = "interger"
                # params[reg_map[src_reg]] = "interger"
                # regtype[sources[1]] = "interger"
                # regtype[sources[0]] = "interger"
                if sources[1] in regtype and src_reg not in regtype:
                    regtype[src_reg]=regtype[sources[1]]
                    regtype[reg_map[src_reg]]=regtype[src_reg]
                    param_types[reg_map[src_reg]] = regtype[src_reg]
                    params[reg_map[src_reg]] = regtype[src_reg]
                    print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                    reg_var = reg_map[src_reg]
                    for mem in list(memory_map):
                        if memory_map[mem] == reg_map[src_reg]:
                            memory_map_type[mem] = regtype[src_reg]
                            memory_map.pop(mem)
                    for reg in list(reg_map):
                        if reg_map[reg] == reg_var:
                            regtype[reg]=regtype[reg_var]
                            reg_map.pop(reg)
                    if reg_map == {} and memory_map == {}:
                        break
                if sources[0] in regtype and sources[1] not in regtype:
                    src_reg=sources[1]
                    regtype[src_reg] = regtype[sources[0]]
                    regtype[reg_map[src_reg]] = regtype[src_reg]
                    param_types[reg_map[src_reg]] = regtype[src_reg]
                    params[reg_map[src_reg]] = regtype[src_reg]
                    print(f"[INFO] 参数 {reg_map[src_reg]} 的传播链: {flow_info[reg_map[src_reg]]}\n")
                    reg_var = reg_map[src_reg]
                    for mem in list(memory_map):
                        if memory_map[mem] == reg_map[src_reg]:
                            memory_map_type[mem] = regtype[src_reg]
                            memory_map.pop(mem)
                    for reg in list(reg_map):
                        if reg_map[reg]==reg_var:
                            regtype[reg]=regtype[reg_var]
                            reg_map.pop(reg)
                    if reg_map == {} and memory_map == {}:
                        break
                if sources[0] not in regtype and sources[1] not in regtype:
                    print(sources[0],sources[1])
                    #扩展接口

        if mnemonic in {"jump_and_link"}:
            print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
            if "$v0" in reg_map:
                reg_map.pop("$v0")
            callee = idc.get_operand_value(addr, 0)
            callee_name = idc.get_func_name(callee)
            if callee_name in all_func_param:
                flags = 0
                cparams = all_func_param[callee_name]
                print(callee_name, cparams)
                if args:
                    args = sort_by_offset(args)
                    print(args)
                    m = 4
                    for arg_var in args:
                        argslist[arg_var] = 'b' + str(m)
                        m = m + 1

                    print(argslist)
                    args.clear()
                # prev_ea = idaapi.prev_head(addr)
                for idx, p in enumerate(cparams):
                    if p in reg_map and idx < 4:
                        param_types[reg_map[p]] = cparams[p]
                        params[reg_map[p]] = cparams[p]
                        regtype[reg_map[p]]=cparams[p]
                        print(reg_map[p])
                        print(f"[INFO] 参数 {reg_map[p]} 的传播链: {flow_info[reg_map[p]]}\n")
                        reg_var = reg_map[p]
                        for mem in list(memory_map):
                            if memory_map[mem] == reg_map[p]:
                                memory_map_type[mem]=regtype[reg_map[p]]
                                memory_map.pop(mem)
                        for reg in list(reg_map):
                            if reg_map[reg] == reg_var:
                                regtype[reg]=regtype[reg_var]
                                reg_map.pop(reg)
                        # if reg_map[p] in reg_map:
                        #     reg_map.pop(reg_map[p])
                        # if p in reg_map:
                        #     reg_map.pop(p)
                        flags = 1
                    if idx >= 4:
                        reg = p.replace("a", "b")
                        print(reg, memory_map, argslist)
                        mem = None
                        for jmem in argslist:
                            if argslist[jmem] == reg:
                                mem = jmem
                                break
                        if mem in memory_map:
                            param_types[memory_map[mem]] = cparams[p]
                            print(f"[INFO] 参数 {memory_map[mem]} 的传播链: {flow_info[memory_map[mem]]}\n")
                            if memory_map[mem] in reg_map:
                                reg_map.pop(memory_map[mem])
                            memory_map.pop(mem)
                            flags = 1
                            m = 4
                            flags = 1
                argslist.clear()
                if flags == 1:
                    flags = 0
                    if reg_map=={} and memory_map=={}:
                        break

        if mnemonic in {"jump"}:
            print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
            target = idc.get_operand_value(addr, 0)
            if target in idautils.Functions():
                callee_name = idc.get_func_name(target)
                if callee_name in all_func_param:
                    cparams = all_func_param[callee_name]
                    print(callee_name, cparams)
                    if args:
                        args = sort_by_offset(args)
                        print(args)
                        m = 4
                        for arg_var in args:
                            argslist[arg_var] = 'b' + str(m)
                            m = m + 1
                        print(argslist)
                        args.clear()
                    for idx, p in enumerate(cparams):
                        print(reg_map,regtype,idx)
                        if p in reg_map and idx < 4:
                            param_types[reg_map[p]] = cparams[p]
                            params[reg_map[p]] = cparams[p]
                            regtype[reg_map[p]]=cparams[p]
                            print(reg_map[p])
                            print(f"[INFO] 参数 {reg_map[p]} 的传播链: {flow_info[reg_map[p]]}\n")
                            reg_var = reg_map[p]
                            for mem in list(memory_map):
                                if memory_map[mem] == reg_map[p]:
                                    memory_map_type[mem] = regtype[reg_map[p]]
                                    memory_map.pop(mem)
                            for reg in list(reg_map):
                                if reg_map[reg] == reg_var:
                                    regtype[reg]=regtype[reg_var]
                                    reg_map.pop(reg)
                            flags = 1
                        if idx >= 4:
                            reg = p.replace("a", "b")
                            print(reg, memory_map, argslist)
                            mem = None
                            for jmem in argslist:
                                if argslist[jmem] == reg:
                                    mem = jmem
                                    break
                            if mem in memory_map:
                                param_types[memory_map[mem]] = cparams[p]
                                print(f"[INFO] 参数 {memory_map[mem]} 的传播链: {flow_info[memory_map[mem]]}\n")
                                if memory_map[mem] in reg_map:
                                    reg_map.pop(memory_map[mem])
                                memory_map.pop(mem)
                                flags = 1
                    argslist.clear()
                    if flags == 1:
                        flags = 0
                        if reg_map == {} and memory_map == {}:
                            break

        if mnemonic in {"jump_register", "jump_and_link_register"}:
            print(f"Decoded instruction at {hex(addr)}: {mnemonic}")
            print(reg_map,regtype)
            func_ea = ida_funcs.get_func(addr).start_ea
            block_start,predecessor_count=get_basic_block_info(addr)
            shortest_path_result = get_shortest_path(func_ea, addr)#获得到当前基本块得最短路径上得指令
            shortest_path_instructions = shortest_path_result["instructions"]
            for instruction in shortest_path_instructions:
                if instruction==addr:
                    break
                reg_value=process_function_instructions(instruction,reg_value)
            if sources[0] in reg_value and reg_value[sources[0]]!=0:
                callee_name=idc.get_func_name(reg_value[sources[0]])
                flags = 0
                #print(callee_name,all_func_param)
                if callee_name in all_func_param and callee_name not in {"sub_425730","printf"}:
                    cparams = all_func_param[callee_name]
                    print(callee_name, cparams)
                    if args:
                        args = sort_by_offset(args)
                        print(args)
                        m = 4
                        for arg_var in args:
                            argslist[arg_var] = 'b' + str(m)
                            m = m + 1
                        print(argslist)
                        args.clear()
                    for idx, p in enumerate(cparams):
                        print(reg_map,regtype,idx)
                        if p in reg_map and idx < 4:
                            param_types[reg_map[p]] = cparams[p]
                            params[reg_map[p]] = cparams[p]
                            regtype[reg_map[p]] = cparams[p]
                            print(reg_map[p])
                            print(f"[INFO] 参数 {reg_map[p]} 的传播链: {flow_info[reg_map[p]]}\n")
                            reg_var=reg_map[p]
                            for mem in list(memory_map):
                                if memory_map[mem]==reg_map[p]:
                                    memory_map_type[mem] = regtype[reg_map[p]]
                                    memory_map.pop(mem)
                            for reg in list(reg_map):
                                if reg_map[reg]==reg_var:
                                    regtype[reg]=regtype[reg_var]
                                    reg_map.pop(reg)
                            flags = 1
                        if idx >= 4:
                            reg = p.replace("a", "b")
                            print(reg, memory_map, argslist)
                            mem = None
                            for jmem in argslist:
                                if argslist[jmem] == reg:
                                    mem = jmem
                                    break
                            if mem in memory_map:
                                param_types[memory_map[mem]] = cparams[p]
                                print(f"[INFO] 参数 {memory_map[mem]} 的传播链: {flow_info[memory_map[mem]]}\n")
                                if memory_map[mem] in reg_map:
                                    reg_map.pop(memory_map[mem])
                                memory_map.pop(mem)
                                flags = 1
                    if "$v0" in reg_map:
                        reg_map.pop("$v0")
                    argslist.clear()
                    if flags == 1:
                        flags = 0
                        if reg_map=={} and memory_map=={}:
                            break
    #print(f"[INFO] 参数 {param} 的传播链: {flow_info}\n")
        # print(param,param_types[param])
    # print(param_types)
    return param_types


def process_function_instructions(item, reg_value):
    start_address = ida_ida.inf_get_min_ea()
    end_address = ida_ida.inf_get_max_ea()
    mnem = idc.print_insn_mnem(item)

    if mnem == "la":
        instruction_type, destination, sources, base_registers, imm = classify_mips_instruction(item)
        if sources[0] != '0':
            reg_value[destination] = int(sources[0], 16)
        if sources[0] == '0' and destination in reg_value:
            reg_value.pop(destination)
    if mnem == "li":
        instruction_type, destination, sources, base_registers, imm = classify_mips_instruction(item)
        if start_address < imm < end_address:
            reg_value[destination] = imm
        elif destination in reg_value:
            reg_value.pop(destination)

    elif mnem == "lw":
        dest_value = idc.print_operand(item, 0)
        if dest_value == "$t9" and dest_value in reg_value:
            reg_value.pop(dest_value)

    elif mnem == "move":
        dest_value = idc.print_operand(item, 0)
        src_value = idc.print_operand(item, 1)
        if src_value in reg_value:
            reg_value[dest_value] = reg_value[src_value]
        elif dest_value == "$t9" and dest_value in reg_value:
            reg_value.pop(dest_value)

    elif mnem == "addiu":
        instruction_type, destination, sources, base_registers, imm = classify_mips_instruction(item)
        # print(hex(item), destination, sources)
        if len(sources) == 1 and destination in reg_value:
            callee = reg_value[destination] + signed_hex_to_decimal(imm)
            reg_value[destination] = callee

        elif len(sources) == 2 and sources[0] in reg_value:
            callee = reg_value[sources[0]] + signed_hex_to_decimal(imm)
            reg_value[destination] = callee

    return reg_value


def get_instructions_in_block(block, next_block_start):
    instructions = []
    ea = block.start_ea
    while ea < block.end_ea:
        mnem = idc.print_insn_mnem(ea)
        if mnem in ["beq", "bne", "beqzl"]:
            # 计算分支目标地址
            instruction_type, destination, sources, base_registers, imm = classify_mips_instruction(ea)
            # print(hex(ea),destination,16,sources)
            target = int(destination, 16)
            delay_slot = idc.next_head(ea, block.end_ea)
            if delay_slot < block.end_ea:
                if next_block_start is not None and target == next_block_start:
                    # 如果目标地址是最短路径下下一个基本块的开始地址，则添加延迟槽
                    instructions.append(ea)
                    instructions.append(delay_slot)

                else:
                    # 如果目标地址不是最短路径下下一个基本块的地址，则跳过延迟槽
                    # print(f"Skipping delay slot at {hex(delay_slot)} as target {hex(target)} != next block {hex(next_block_start) if next_block_start else 'None'}")
                    instructions.append(ea)
                    instructions.append(delay_slot)
                ea = delay_slot
        else:
            instructions.append(ea)  # 普通指令始终添加
        ea = idc.next_head(ea, block.end_ea)
    return instructions


def get_shortest_path(func_ea, target_ea):
    func = ida_funcs.get_func(func_ea)
    if not func:
        print(f"No function found at {hex(func_ea)}")
        return {"blocks": [], "instructions": []}

    flow_chart = idaapi.FlowChart(func)
    visited = set()
    queue = deque([(flow_chart[0], [])])

    while queue:
        current_block, path = queue.popleft()

        if current_block.start_ea in visited:
            continue

        visited.add(current_block.start_ea)
        new_path = path + [current_block]

        if current_block.start_ea <= target_ea < current_block.end_ea:
            # print("Shortest Path Found:")
            all_instructions = []
            for i, block in enumerate(new_path):
                next_block_start = new_path[i + 1].start_ea if i + 1 < len(new_path) else None
                # print(f"  Block Start: {hex(block.start_ea)} | End: {hex(block.end_ea)}")
                instructions = get_instructions_in_block(block, next_block_start)
                all_instructions.extend(instructions)

            return {
                "blocks": new_path,
                "instructions": all_instructions
            }

        for succ in current_block.succs():
            queue.append((succ, new_path))

    print(f"No path found from start to {hex(target_ea)}")
    return {"blocks": [], "instructions": []}


def get_callee(func_name):
    """
    获取当前函数直接调用的所有函数。
    :param func_name: 函数名称
    :return: 被调用函数的列表
    """
    reg_value = {}

    func_ea = idc.get_name_ea_simple(func_name)

    if func_ea == idc.BADADDR:
        print(f"Function {func_name} not found.")
        return []
    # instructions=get_function_instructions(func_ea)
    callees = []
    for item in idautils.FuncItems(func_ea):
        if idaapi.is_call_insn(item):
            callee = idc.get_operand_value(item, 0)
            callee_name = idc.get_func_name(callee)
            if callee_name:
                callees.append(callee_name)

        # 检查跳转指令（如 j, b）
        if idc.print_insn_mnem(item) in ["j", "b"]:
            target = idc.get_operand_value(item, 0)
            if target in idautils.Functions():
                callee_name = idc.get_func_name(target)
                if callee_name:
                    callees.append(callee_name)
        if idc.print_insn_mnem(item) in ["jr", "jalr"]:
            if idc.print_insn_mnem(item) == "jr":  # 获取源操作数
                src_op_type = idc.get_operand_type(item, 0)
                src_op_value = idc.print_operand(item, 0)
            if idc.print_insn_mnem(item) == "jalr":
                src_op_type = idc.get_operand_type(item, 1)
                src_op_value = idc.print_operand(item, 1)

            if src_op_value in {"$t9"}:
                disam = idc.GetDisasm(item)
                callee_name_a = None
                # if  ";" not in disam and  "#" not in disam:
                func_ea = ida_funcs.get_func(item).start_ea
                block_start, predecessor_count = get_basic_block_info(item)
                shortest_path_result = get_shortest_path(func_ea, item)  # 获得到当前基本块得最短路径上得指令
                shortest_path_instructions = shortest_path_result["instructions"]
                for instruction in shortest_path_instructions:
                    if instruction == item:
                        break
                    reg_value = process_function_instructions(instruction, reg_value)
                # print(hex(block_start),predecessor_count,shortest_path_instructions,reg_value,src_op_value)
                if src_op_value in reg_value and reg_value[src_op_value] != 0:
                    callee_name = idc.get_func_name(reg_value[src_op_value])
                    if callee_name:
                        callees.append(callee_name)
    return list(set(callees))

def contains_loop(func_ea):
    """
    判断函数是否包含循环结构。
    :param func_ea: 函数起始地址。
    :return: True 如果包含循环，否则 False。
    """
    func = ida_funcs.get_func(func_ea)
    if not func:
        return False

    flow_chart = idaapi.FlowChart(func)
    visited = set()
    stack = []

    def dfs(block):
        if block.start_ea in visited:
            return False

        visited.add(block.start_ea)
        stack.append(block.start_ea)

        for succ in block.succs():
            if succ.start_ea in stack or dfs(succ):
                return True

        stack.pop()
        return False

    for block in flow_chart:
        if dfs(block):
            return True

    return False

def dfs_traverse_function(func_name, visited=None, result=None):
    """
    使用深度优先遍历，确保所有子函数都处理完成后再记录当前函数。
    :param func_name: 起始函数名称
    :param visited: 已访问的函数集合
    :param result: 结果列表
    """
    if visited is None:
        visited = set()
    if result is None:
        result = []

    if func_name in visited:
        return result

    visited.add(func_name)
    #print(func_name)
    callees = get_callee(func_name)

    # 深度优先处理子函数
    for callee in callees:
        if callee not in visited:
            #print(func_name,callees)
            dfs_traverse_function(callee, visited, result)

    # 在递归回溯阶段记录当前函数
    if func_name not in result:  # 防止重复加入
        result.append(func_name)
    return result

def count_function_calls(func_addr):
    """
    统计某个函数中调用的次数。
    :param func_addr: 函数地址
    :return: 调用次数
    """
    call_count = 0
    for item in idautils.FuncItems(func_addr):
        # 获取当前指令的助记符
        mnemonic = idc.print_insn_mnem(item)

        # 检查函数调用指令（排除 jalr）
        if idaapi.is_call_insn(item) and mnemonic not in {"jalr"}:
            call_count += 1

        # 检查跳转指令（j, b），并验证是否跳转到有效的函数地址
        if mnemonic in ["j", "b"]:
            target = idc.get_operand_value(item, 0)
            if target in idautils.Functions():
                call_count += 1

        # 检查跳转寄存器指令（jr, jalr）
        if mnemonic in ["jr", "jalr"]:
            disam = idc.GetDisasm(item)
            src_op_value = idc.print_operand(item, 0)
            # 如果 disasm 包含注释符号（如 ; 或 #），则认为是函数调用
            if (";" in disam or "#" in disam) and src_op_value not in {"$v0"}:
                call_count += 1

        # 检查系统调用指令（syscall），虽然未直接影响 call_count，但可根据需要扩展功能
        if mnemonic == "syscall":
            pass

    return call_count

def get_funlist():
    global all_functions
    global loop_functions

    # 统计所有函数调用次数
    func_dict = {}
    for func_ea in idautils.Functions():
        call_count=count_function_calls(func_ea)
        if contains_loop(func_ea):
            if call_count<=4:
                loop_functions.append(func_ea)
        else:
            if call_count>0 and call_count <=4:
                loop_functions.append(func_ea)
    #for func in idautils.Functions():
    for func in loop_functions:
        func_name = idc.get_func_name(func)
        count = count_function_calls(func)
        func_dict[func_name] = count
        #print(func_name,hex(func))

    # 按调用次数排序
    order_func_dict = sorted(func_dict.items(), key=lambda x: x[1], reverse=False)
    print(order_func_dict)
    #print(order_func_dict)

    # 深度优先遍历所有函数
    visited = set()
    for func_name in dict(order_func_dict):
        if func_name not in visited:  # 防止重复分析
            #print(func_name)
            result = dfs_traverse_function(func_name, visited)
            all_functions.extend(result)  # 合并结果

    # 确保最终结果中无重复
    all_functions = list(dict.fromkeys(all_functions))

    # 输出结果
    print("Functions in order after all callees return:")
    return  all_functions

# def get_funlist():
#     global all_functions
#
#
#
#     # 统计所有函数调用次数
#     func_dict = {}
#     funcs = idautils.Functions()
#     for func in funcs:
#         func_name = idc.get_func_name(func)
#         if func_name=="":
#             print("Function not found:",hex(func))
#         count = count_function_calls(func)
#         func_dict[func_name] = count
#         #print(func_name, hex(func),count)
#     # 按调用次数排序
#     order_func_dict = sorted(func_dict.items(), key=lambda x: x[1], reverse=False)
#     #print(order_func_dict)
#
#     # 深度优先遍历所有函数
#     visited = set()
#     for func_name in dict(order_func_dict):
#         if func_name not in visited:  # 防止重复分析
#             #print(func_name)
#             result = dfs_traverse_function(func_name, visited)
#             all_functions.extend(result)  # 合并结果
#
#     # 确保最终结果中无重复
#     all_functions = list(dict.fromkeys(all_functions))
#
#     # 输出结果
#     print("Functions in order after all callees return:")
#     return all_functions


def analyze_function(func_addr):
    global all_flows
    print("=====================start function analysis===========================")
    print(f"analyze_function:{hex(func_addr)}")
    all_flows[idc.get_func_name(func_addr)] = ""
    blocks, max_path = get_function_basic_blocks(func_addr)
    if len(blocks) <= 2:
        i=0
        j=0
        print(hex(func_addr))
        param_types, params, param_mem, stack_var = analyze_function_parameters(func_addr)
        for ins in blocks[0]['instructions']:
            if idc.print_insn_mnem(ins) in ["jalr","jal","bal","b","j"]:
                i = i + 1
        if i == 1:
            for ins in blocks[0]['instructions']:
                if idc.print_insn_mnem(ins) in ["jalr"] and param_mem != []:
                    callee_name = extract_function_name(idc.GetDisasm(ins))
                    if callee_name != None:
                        print(f"{func_addr:x} wrapper function {callee_name}")
                        if callee_name in all_func_param:
                            return all_func_param[callee_name]
                        # else:
                        #     all_func_param[callee_name] = analyze_function(idc.get_name_ea_simple(callee_name))
                        #     return all_func_param[callee_name]
                if idc.print_insn_mnem(ins) in ["b","j"] and params==[]:
                    callee = idc.get_operand_value(ins, 0)
                    callee_name = idc.get_func_name(callee)
                    if callee_name != None:
                        print(hex(ins), hex(callee))
                        print(f"{func_addr:x} wrapper function {callee_name}")
                        if callee_name in all_func_param:
                            return all_func_param[callee_name]

                if idc.print_insn_mnem(ins) in ["jal","bal"] and (param_mem != []):
                    callee = idc.get_operand_value(ins, 0)
                    print(hex(ins),hex(callee))
                    callee_name = idc.get_func_name(callee)
                    if callee_name != None:
                        print(f"{func_addr:x} wrapper function {callee_name}")
                        if callee_name in all_func_param:
                            return all_func_param[callee_name]

        for ins in blocks[0]['instructions']:
            if idc.print_insn_mnem(ins) in ["jr"]:
                j = j + 1
            if j == 1 and idc.print_operand(ins,0)!="$ra":
                callee = idc.get_operand_value(ins, 0)
                print(hex(ins), hex(callee))
                callee_name = extract_function_name(idc.GetDisasm(ins))
                if callee_name != None:
                    print(f"{func_addr:x} wrapper function {callee_name}")
                    if callee_name in all_func_param:
                        return all_func_param[callee_name]
                    else:
                        all_func_param[callee_name] = analyze_function(idc.get_name_ea_simple(callee_name))
                        return all_func_param[callee_name]

    if len(max_path) == 3 and idc.print_insn_mnem(max_path[1]) == 'j' and max_path[2] in all_functions:
        callee_name = idc.get_func_name(max_path[2])
        print(f"{func_addr:x} wrapper function {callee_name}")
        if callee_name != None:
            print(f"{func_addr:x} wrapper function {callee_name}")
            if callee_name in all_func_param:
                return all_func_param[callee_name]
            else:
                all_func_param[callee_name] = analyze_function(idc.get_name_ea_simple(callee_name))
                return all_func_param[callee_name]

    func_name = idc.get_func_name(func_addr)
    if func_name in all_func_param:
        return all_func_param[func_name]
    # 确定有几个参数

    param_types, params, param_mem, stack_var = analyze_function_parameters(func_addr)
    param_types = track_parameter_flow(func_addr, params, param_types, param_mem, stack_var)
    print(f"\nFunction: {func_name} ({hex(func_addr)})")
    if param_types:
        for reg, reg_type in param_types.items():
            print(f"  {reg}: {reg_type}")
    else:
        print("  No parameters detected.")

    all_flows[func_name] = {"address": func_addr, "param_types": param_types.copy()}
    return param_types

def analyze_all_functions():
    """
    遍历程序中的所有函数，并分析其参数。
    """
    global all_functions
    functions = get_funlist()
    print(functions)
    all_functions = [idc.get_name_ea_simple(fun_ame) for fun_ame in functions]
    for func_addr in all_functions:
        func_name = idc.get_func_name(func_addr)
        #print(func_name,hex(func_addr))
        if func_name in all_flows:
            continue
        all_func_param[func_name] = analyze_function(func_addr)

all_functions = []
all_func_param = {}
all_flows = {}
fpflag=0
loop_functions = []

# if __name__ == "__main__":
#     #global all_func_param
#     analyze_all_functions()
#     print("**********************function parameters******************************************")
#
#     funcs = json.load(open(r"E:\LLM\parameters.json", 'r'))
#     func_names = [f for f in funcs]
#     fum = len(func_names)
#     print(f"已加载函数数量: funcs = {len(funcs)}, all_func_param = {len(all_func_param)}")
#
#     para_num = 0#参数个数
#     pnenum = 0#参数个数识别错误的函数个数
#     pnenum2 = 0#类型判断错误的参数个数
#     fumnum = 0#类型判断错误的函数个数
#     for i in funcs:
#         flag = 0
#         t_arg = []
#         if "arg_type" in funcs[i]:#函数包含参数
#             num = len(funcs[i]["arg_type"])#函数参数的个数
#             for arg in funcs[i]["arg_type"]:
#                 if "*" in arg or "[" in arg:
#                     t_arg.append("pointer")
#                 else:
#                     t_arg.append("interger")
#
#             if i in all_func_param:
#                 if len(funcs[i]["arg_type"]) != len(all_func_param[i]):
#                     print(f"函数 {i}, 参数数量不匹配")
#                     pnenum = pnenum + 1
#                     fumnum = fumnum + 1
#                 else:
#                     #param_registers = ["$a0", "$a1", "$a2", "$a3"]
#                     #print(f"{t_arg}, {all_func_param[i]}")
#                     print(f"{i}: {t_arg}")
#
#                     for a, b in enumerate(all_func_param[i]):
#                         if a < len(t_arg) and b in all_func_param[i]:
#                             if t_arg[a] != all_func_param[i][b] and \
#                                ("pointer" == t_arg[a] or "pointer" == all_func_param[i][b]):
#                                 pnenum2 = pnenum2 + 1
#                                 flag = 1
#                                 print(f"函数 {i}，参数 {b} 指针判断错误")
#                     if flag == 1:
#                         fumnum = fumnum + 1
#             else:
#                 print(f"警告: 缺少函数 '{i}' 在 all_func_param 中")
#
#             print(f"{i}: {all_func_param.get(i, '未找到')}")
#         else:
#             if i in all_func_param and len(all_func_param[i])!= 0:
#                 print(f"函数 {i}, 参数数量不匹配")
#                 pnenum = pnenum + 1
#                 num = 0
#             if i not in all_func_param:
#                 print(f"警告: 缺少函数 '{i}' 在 all_func_param 中")
#         para_num = para_num + num
#     print(fum, para_num, fumnum, pnenum, pnenum2)



def gen_disasm(func_name):
    # 查找函数的地址
    func_ea = idc.get_name_ea_simple(func_name)

    if func_ea != idc.BADADDR:  # 确保找到函数地址
        # 生成汇编代码
        disasm_lines = []
        for head in idautils.Heads(func_ea, idc.find_func_end(func_ea)):
            disasm_lines.append(f"{hex(head)} {idc.generate_disasm_line(head, 0)}")

        # 输出汇编代码
        return disasm_lines
    else:
        print(f"Function {func_name} not found.")


def generate_copy_function_prompt(asm_code,params,calles,copy_fun):
    copy_fun_info=[]
    assemble={}
    subfun=[]
    if calles:
        for fun in calles:
            if fun in copy_fun:
                copy_fun_info.append(fun)
            if fun not in copy_fun:
                assemble[fun]=gen_disasm(fun)
                subfun.append(fun)
        print(copy_fun_info,subfun)
    return f"""
            You will be provided with the assembly code of a function.Your task is to determine whether the function is a memory or string copy function.

            A copy function is defined as a function whose **primary purpose** is to transfer data from a source buffer to a destination buffer, possibly with minor per-element transformations such as case conversion.
            Judge the function based on the overall behavior and intent, not by individual instructions.

            ---

            ### 1. What Qualifies as a Copy Function
            Classify a function as a copy function if its dominant behavior includes:

            - Memory copying or moving (e.g., memcpy, memmove)
            - String copying (e.g., strcpy-like behavior)
            - String concatenation (e.g., strcat-like behavior)
            - Copying with minor transformations (e.g., uppercase/lowercase conversion)
            - Delegating copying to subfunctions (wrapper or forwarding functions)

            The presence or absence of specific instructions (e.g., load/store, loops) does **not** alone determine classification.

            ---

            ### 2. Allowed Operations
            These operations may appear and do **not** disqualify the function:

            - Simple case conversions
            - Bitwise operations for implementation or alignment (xor, and, or, shifts)
            - Pointer arithmetic or address calculations
            - Loop unrolling or optimized control flow
            - Safety or bounds checks (e.g., __chk_fail)
            - Calls to unknown helper functions that appear to assist data transfer

            ---

            ### 3. Disallowed Operations (Not a Copy Function)
            Return "No" if the function primarily performs any of the following:

            - Parsing, validation, normalization, or filtering of data
            - Conditional or selective copying based on content semantics
            - Encoding, compression, or cryptographic transformations
            - Computing checksums, hashes, or other semantic summaries
            - Comparing data without transferring it (e.g., strcmp, memcmp)
            - Writing to the destination in a way that is **not derived from the source**

            ---

            ### 4. Key Semantic Test
            Consider the following:
            If a change in the source data does **not** produce nearly identical changes in the destination data, the function is **not** a copy function.

            This ensures that functions that modify, encode, or parse the data are correctly excluded.

            ---

            ### 5. Function Input
            1.Function parameters: {params}
            2.Function assembly code: {asm_code}
            3.Subfunctions identified as copy functions are: {copy_fun_info}
    #        - Other subfunctions are: {subfun}
    #        - Assembly code for other child functions are: {assemble}

            ---

            ### 6. Final Decision
            Decide based on the **dominant behavior and intent**:

            - Return "Yes" if the function is a true copy function.
            - Return "No" if it is not a copy function or primarily transforms, parses, or analyzes the data.

            **Return only "Yes" or "No".**


        """

#     return f"""
#     You will be provided with the assembly code of a function, along with its parameters and their types. Your task is to analyze the function's assembly code and logical functionality to determine whether the function qualifies as a copy function based on the given features. Remember the following features.
#
#     ---
#
#     ### **1. Types of Copy Operations**
#     A function qualifies as a copy function if it primarily transfers or appends data. This includes:
#     - **String Copying**: Transfers a string from the source to the destination (e.g., 'strcpy').
#     - **String Concatenation**: Locates the null terminator ('\\0') in the destination string and appends the source string starting at that position (e.g., 'strcat').
#     - **Memory Copying**: Transfers raw data directly from the source to the destination (e.g., 'memcpy').
#     - **Simple Character Conversion**: Copies data while performing minor transformations such as **case changes (uppercase to lowercase, lowercase to uppercase)**.
#
#     🚨 **Exclusion:**
#     - Functions that perform **complex encoding transformations** (e.g., Base64 encoding, Huffman coding, or any cryptographic encoding) **are not** considered copy functions.
#
#     ---
#
#     ### **2. Key Characteristics of Copy Functions**
#     #### **Data Transfer**
#     - The primary task of the function must be **moving data** from a source to a destination.
#     - **Important:** If the function **only compares** values (e.g., using 'strcmp' or 'memcmp'), it is **not** a copy function.
#
#     #### **Parameters**
#     - **Source**: A pointer to the data being copied or appended.
#     - **Destination**: A pointer where data is stored.
#     - **Length** (optional): The number of bytes or characters to transfer.
#     - **Stop Condition** (optional): A condition that terminates the operation, such as encountering a null terminator ('\\0') or a specific value.
#
#     ---
#
#     ### **3. Encoding Conversion & Transformations**
#     ✅ **Allowed (Copy Function)**
#     - **Simple case transformations** (e.g., converting `A-Z` to `a-z` while copying).
#
#     ❌ **Not Allowed (Not a Copy Function)**
#     - **Encoding conversions** (e.g., Base64, UTF-16 to UTF-8, or compression algorithms).
#     - **Bitwise manipulations** that significantly alter the data beyond simple case transformations.
#
#     ---
#
#     ### **4. Control Flow**
#     - **Copy functions typically include one or both of the following**:
#       - **Loop Structures**: Iterative operations to process data (e.g., finding the null terminator, copying characters, or appending strings).
#       - **Function Calls**: Calls to subfunctions that assist in copying or transforming data.
#
#     🚨 **Exclusion:**
#     - If a function **primarily involves comparison operations** (e.g., `strcmp`, `memcmp`), it should **not** be classified as a copy function.
#     - If neither a loop nor a function call is present, the function is unlikely to be a copy function.
#
#     ---
#
#     ### **5. Register and Memory Interaction**
#     - **Parameter Passing**: Parameters are passed between registers (e.g., '$a0', '$a1', '$a2', '$v0', '$v1') and memory.
#     - **Key Instructions**: In a **copy operation**, the following must coexist:
#       - **Load Operations** ('lbu', 'lw'): Load data from memory into registers.
#       - **Store Operations** ('sb', 'sw'): Store data from registers into memory.
#       - **Branch Operations** ('bnez', 'beqz'): Control flow for loops or stopping conditions.
#
#     🚨 **Exclusion:**
#     - If **no store operations** (`sw`, `sb`) are present, the function is **not** a copy function.
#     - Functions that **only compare** values and never store new data should **not** be classified as copy functions.
#
#     ---
#     ### **6. Handling Child Functions**
#     - If a function calls child functions whose behavior is not clearly defined:
#       - First, analyze the behavior of those child functions.
#       - Then, determine whether the main function qualifies as a copy function based on their combined behavior.
#
#
#     1.The function's parameters and types:{params}.
#     2.The function's assembly code:\n{asm_code}.
#     3.Subfunctions identified as copy functions are: {copy_fun_info}
#        - Other subfunctions are: {subfun}
#        - Assembly code for other child functions are: {assemble}
#
#     5. Only provide the final result:
#        - If it is a copy function, answer: "Yes".
#        - If it is not, answer: "No".
# """

    # prompt = {
    #     "instruction": f"Analyze the provided assembly code strictly following these rules to determine if it implements a copy function. "
    #                    f"1. The function's parameters and types: {params}.\n"
    #                    f"2. The function's assembly code:\n{asm_code}.\n"
    #                    f"3. Subfunctions identified as copy functions are: {copy_fun_info}\n"
    #                    f"   - Other subfunctions are: {subfun}\n"
    #                    f"   - Assembly code for other child functions are: {assemble}\n"
    #                    f"4. Reply ONLY with 'Yes' or 'No'.",
    #     "criteria": {
    #         "required_features": [
    #             {
    #                 "id": 1,
    #                 "description": "Data transfer operations",
    #                 "checks": [
    #                     "Contains store instructions (sw/sb/sd) OR",
    #                     "Calls core copy functions (memcpy/strcpy/strcat)"
    #                 ]
    #             },
    #             {
    #                 "id": 2,
    #                 "description": "Clear data flow path",
    #                 "checks": [
    #                     "Identifiable source register (e.g., $a0/x0/r0)",
    #                     "Identifiable destination register (e.g., $a1/x1/r1)"
    #                 ]
    #             },
    #             {
    #                 "id": 3,
    #                 "description": "No explicit length initialization in memset",
    #                 "checks": [
    #                     "Reject if the function explicitly initializes length in memset (e.g., li $a2, 0x10)",
    #                     "Length for memset must be passed as a parameter or derived from data"
    #                 ]
    #             }
    #         ],
    #         "allowed_features": [
    #             "Memory initialization (memset) BEFORE copying",
    #             "Length calculation (strlen/strnlen)",
    #             "Terminator location (memchr)",
    #             "Alignment operations (__memalign)",
    #             "Buffer overflow checks (__chk_fail)",
    #             "Case conversion during copying (e.g., uppercase to lowercase, lowercase to uppercase)",
    #             "Case conversion via function calls (e.g., tolower, toupper)",
    #             "Case conversion via lookup tables"
    #         ],
    #         "exclusion_rules": [
    #             {
    #                 "id": "C1",
    #                 "description": "Data transformation operations",
    #                 "patterns": [
    #                     "Cryptographic instructions (aesenc/sha256rnd)",
    #                     "Encoding conversions (utf8enc/utf16enc)",
    #                     "Compression routines (zip/unzip)",
    #                     "Checksum/hash generation (crc32/md5)"
    #                 ]
    #             },
    #             {
    #                 "id": "C2",
    #                 "description": "Explicit length initialization in memset",
    #                 "patterns": [
    #                     "li with immediate value in memset (e.g., li $a2, 0x10)",
    #                     "addiu with immediate value in memset (e.g., addiu $a2, 16)"
    #                 ]
    #             }
    #         ],
    #         "subfunction_handling": {
    #             "definitive_copy_functions": copy_fun_info,  # 使用传入的已知拷贝函数列表
    #             "allowed_helpers": [
    #                 "memset", "strlen", "strnlen",
    #                 "memchr", "__memalign",
    #                 "tolower", "toupper"  # 允许调用大小写转换函数
    #             ],
    #             "wrapper_rules": [
    #                 "Wrapper functions MUST call at least one core copy function (memcpy/strcpy/strcat)",
    #                 "Helper functions (e.g., memset, strlen) MUST be called BEFORE the core copy operation",
    #                 "Helper functions MUST eventually lead to a core copy operation"
    #             ],
    #             "inheritance_rule": "Functions calling known copy functions inherit the copy function classification ONLY if no explicit length initialization in memset is present"
    #         }
    #     },
    #     "analysis_workflow": [
    #         {
    #             "step": 1,
    #             "action": "Reject if no store_ops AND no core_copy_calls",
    #             "fast_fail": True
    #         },
    #         {
    #             "step": 2,
    #             "action": "Verify source->destination data flow pattern",
    #             "methods": [
    #                 "Register tracing between load/store ops",
    #                 "Parameter register analysis ($a0->$a1 etc)"
    #             ]
    #         },
    #         {
    #             "step": 3,
    #             "action": "Check for allowed transformations",
    #             "checks": [
    #                 "Ensure any case conversion (e.g., A->a, b->B) is performed during copying",
    #                 "Allow case conversion via function calls (e.g., tolower, toupper)",
    #                 "Allow case conversion via lookup tables",
    #                 "Reject if transformations significantly alter data (e.g., encoding, encryption)"
    #             ]
    #         },
    #         {
    #             "step": 4,
    #             "action": "Check for explicit length initialization in memset",
    #             "checks": [
    #                 "Reject if the function explicitly initializes length in memset (e.g., li $a2, 0x10)",
    #                 "Length for memset must be passed as a parameter or derived from data"
    #             ]
    #         },
    #         {
    #             "step": 5,
    #             "action": "Check wrapper function rules",
    #             "checks": [
    #                 "If the function is a wrapper, ensure it calls at least one core copy function",
    #                 "Ensure helper functions (e.g., memset, strlen) are called BEFORE the core copy operation",
    #                 "Ensure helper functions eventually lead to a core copy operation"
    #             ]
    #         },
    #         {
    #             "step": 6,
    #             "action": "Final confirmation of allowed/forbidden patterns",
    #             "checks": [
    #                 "No cryptographic/encoding ops",
    #                 "No pure helper-only logic"
    #             ]
    #         }
    #     ],
    #     "response_format": {
    #         "requirements": [
    #             "STRICTLY output only 'Yes' or 'No'",
    #             "No explanations/comments allowed"
    #         ],
    #         "examples": [
    #             {"input": "loop with sb/lbu and case conversion via arithmetic", "output": "Yes"},
    #             {"input": "loop with sb/lbu and case conversion via tolower function", "output": "Yes"},
    #             {"input": "loop with sb/lbu and case conversion via lookup table", "output": "Yes"},
    #             {"input": "aesenc + memcpy", "output": "No"},
    #             {"input": "wrapper calling memset before memcpy with parameter length", "output": "Yes"},
    #             {"input": "wrapper calling memset before memcpy with explicit length (li $a2, 0x10)", "output": "No"},
    #             {"input": "wrapper calling memset after memcpy", "output": "No"},
    #             {"input": "wrapper calling only memset", "output": "No"}
    #         ]
    #     }
    # }
    # prompt = json.dumps(prompt, indent=2)
    return prompt


#4.If a function performs a copy operation (which may include calling encoding conversion functions) but also calls other functions unrelated to copying, it should not be classified as a copy function.

def analyze_assembly_code_A(assembly_code,parameters,calles,copy_fun):
    prompt=generate_copy_function_prompt(assembly_code,parameters,calles,copy_fun)

    #print(prompt)
    # 调用 OpenAI Chat API
    try:
        #print(parameters)
        response = client.chat.completions.create(
            model="deepseek-chat",  # 或使用 "gpt-3.5-turbo" 以降低成本
            messages=[
                {"role": "system",
                 "content": "You are Frederick, an AI expert in assembly language security analysis. Your task is to decide whether a given function is a copy or not."},
                {"role": "user",
                 "content": prompt}
            ],
            max_tokens=1000,  # 设置输出长度，可以根据需要调整
            temperature=0,  # 温度值低可以生成更准确的回答
            top_p =1
        )

        # 输出分析结果
        analysis = response.choices[0].message.content.strip()

        if "Yes" in analysis:
            print(f"✅ 识别为拷贝函数: {funcname}")
            copy_fun.append(funcname)
        else:
            print(f"❌ 不是拷贝函数: {funcname}")

        return copy_fun

    except Exception as e:
        return f"分析时出错: {e}"
def analyze_assembly_code_B(assembly_code,parameters,calles,copy_fun):
    prompt=generate_copy_function_prompt(assembly_code,parameters,calles,copy_fun)

    #print(prompt)
    # 调用 OpenAI Chat API
    try:
        #print(parameters)
        response = client.chat.completions.create(
            model="deepseek-chat",  # 或使用 "gpt-3.5-turbo" 以降低成本
            messages=[
                {"role": "system",
                 "content": "You are Frederick, an AI expert in assembly language security analysis. Your task is to decide whether a given function is a copy or not."},
                {"role": "user",
                 "content": prompt}
            ],
            max_tokens=1000,  # 设置输出长度，可以根据需要调整
            temperature=0,  # 温度值低可以生成更准确的回答
            top_p =1
        )

        # 输出分析结果
        analysis = response.choices[0].message.content.strip()

        if "Yes" in analysis:
            print(f"✅ 识别为拷贝函数: {funcname}")
            copy_fun.append(funcname)
        else:
            print(f"❌ 不是拷贝函数: {funcname}")

        return copy_fun

    except Exception as e:
        return f"分析时出错: {e}"


if __name__ == "__main__":
    #global all_func_param
    analyze_all_functions()
    print("**********************function parameters******************************************")
    Potential_mem_funlist = []
    memcpy=['sub_4017FC', 'sub_401F34', 'sub_402510', 'sub_4027AC', 'sub_41EA70', 'sub_41EBB0', 'sub_41F290', 'sub_41F2C0', 'sub_41F300', 'sub_41F4C0', 'sub_41F660', 'sub_41F780', 'sub_41F7A0', 'sub_41F7F0', 'sub_41F840', 'sub_41F880', 'sub_41F8B0', 'sub_41F8E0', 'sub_41F950', 'sub_427950']


    #funcs = json.load(open(r"E:\LLM\parameters.json", 'r'))
    funcs = json.load(open(r"D:\all_ida_json\gcc-4.6.4-O0-mips.json", 'r'))

    func_names = [f for f in funcs]

    for i in all_func_param:
        func_ea = idc.get_name_ea_simple(i)
        call_count=count_function_calls(func_ea)
        if ((contains_loop(func_ea) and call_count <= 1 or call_count>0 and call_count <= 1 and contains_loop(func_ea)==False)):
            # if  i in func_names :
            j=0
            for a, b in enumerate(all_func_param[i]):
                if b in all_func_param[i]:
                    if "pointer" == all_func_param[i][b]:
                        j=j+1
            if j==2 and len(all_func_param[i])<=4:
                if contains_loop(func_ea) and call_count <= 4:
                    Potential_mem_funlist.append(i)
                if call_count>0 and call_count <= 4 and contains_loop(func_ea)==False:
                    Potential_mem_funlist.append(i)
    print(len(Potential_mem_funlist),Potential_mem_funlist)
    for i in range(0,5,1):

        client = OpenAI(api_key="xxx", base_url="https://api.deepseek.com")
        #client = OpenAI(api_key="sk-BoyS42mEMDAfqLwMb7sRY7kLbbcQqyzmJ42LVOkqnnoYPoTQ", base_url="https://tianshu.tones-ai.com/v1")

        func_dict = {}
        start = time.time()
        copy_fun=[]
        for funcname in Potential_mem_funlist:
            assembly = gen_disasm(funcname)
            assembly_code = "\n".join(assembly)
            assembly_code = funcname + "\n" + assembly_code
            calles=get_callee(funcname)
            if calles==[]:
                copy_fun = analyze_assembly_code_A(assembly_code, all_func_param[funcname],calles,copy_fun)
            else:
                copy_fun = analyze_assembly_code_B(assembly_code, all_func_param[funcname], calles, copy_fun)

        print("\n📌 **识别出的拷贝函数列表**:")
        print(len(copy_fun),copy_fun)
        for fun in memcpy:
            if fun not in copy_fun:
                print(fun)
        end = time.time()
        print(end - start)