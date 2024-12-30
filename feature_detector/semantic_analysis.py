import logging
from anytree import Node

import global_params
from cfg_builder.opcodes import *
from cfg_builder.utils import *

# magic value
HASH_TO_HEX = 353073666
OWNER = "owner"
BOOL_ACTIVE = "ACTIVE"
BOOL_START = "START"

CONSTANT_ONES_159 = BitVecVal((1 << 160) - 1, 256)

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

# THIS IS TO DEFINE A SKELETON FOR ANALYSIS
# FOR NEW TYPE OF ANALYSIS: add necessary details to the skeleton functions

def find_mem_real_info(mem_real, index, length):
    for info in mem_real:
        if (info["start"] == index and info["end"] == index + length - 1):
            return info["value"]
    
    return None

def find_mem_real_info_s(mem_real, argsOffset, argsSize):
    temp_possible_amounts = []
    for info in mem_real:
        if (info["start"] >= argsOffset and info["end"] <= argsOffset + argsSize - 1):
            temp_possible_amounts.append(info)

    return temp_possible_amounts


def precision_loss_analysis(
    opcode,
    stack,
    mem,
    mem_real,
    global_state,
    global_problematic_pcs,
    current_func_name,
    g_src_map,
    path_conditions_and_vars,
    solver,
    instructions,
    g_slot_map,
):

    if opcode == "JUMP":
        source_code = ""
        if g_src_map:
            source_code = g_src_map.get_source_code(global_state["pc"])
            if source_code in g_src_map.func_call_names:

                if (source_code.startswith("transferFrom")):
                    amount = stack[1]
                    to = stack[2]
                    from_param = stack[3]
                    check_operator_order_issue(amount, global_state, global_problematic_pcs)
                    # check_indivisible_amount(amount, path_conditions_and_vars, global_state, global_problematic_pcs)
                    token_address = path_conditions_and_vars["Ia"]
                    add_token_flow(
                        token_address, from_param, to, amount, global_state, path_conditions_and_vars, global_problematic_pcs
                    )

                elif (source_code.startswith("transfer")):
                    to = stack[2]
                    amount = stack[1]
                    check_operator_order_issue(amount, global_state, global_problematic_pcs)
                    from_param = path_conditions_and_vars["Is"]
                    token_address = path_conditions_and_vars["Ia"]
                    add_token_flow(
                        token_address, from_param, to, amount, global_state, path_conditions_and_vars, global_problematic_pcs
                    )
                
                elif (source_code.startswith("_transfer")):
                    amount = stack[1]
                    to = stack[2]
                    from_param = stack[3]
                    check_operator_order_issue(amount, global_state, global_problematic_pcs)
                    token_address = path_conditions_and_vars["Ia"]
                    add_token_flow(
                        token_address, from_param, to, amount, global_state, path_conditions_and_vars, global_problematic_pcs
                    )

                elif (source_code.startswith("_mint")):
                    amount = stack[1]
                    to = stack[2]
                    check_operator_order_issue(amount, global_state, global_problematic_pcs)
                    from_param = path_conditions_and_vars["Ia"]
                    token_address = path_conditions_and_vars["Ia"]
                    add_token_flow(
                        token_address, from_param, to, amount, global_state, path_conditions_and_vars, global_problematic_pcs
                    )

                # use safeERC20
                # safeTransferFrom(contract IERC20 token, address from, address to, uint256 value)
                elif (".safeTransferFrom" in source_code):
                    jump_target = stack[0]
                    amount = stack[1]
                    to =  stack[2]
                    from_param = stack[3]
                    token_address = stack[4]

                    check_operator_order_issue(amount, global_state, global_problematic_pcs)

                    add_token_flow(
                        token_address, from_param, to, amount, global_state, path_conditions_and_vars, global_problematic_pcs
                    )

                    # argsOffset = stack[3]
                    # argsSize = stack[4]
                    # operator_order = []
                    # var_to_operator = global_state["var_to_operator"]
                    # if argsSize == 132:
                    #     amount = mem[argsOffset + 4 + 32 + 32 + 32]
                    #     operator_order = get_expr_operators_order(var_to_operator, amount, operator_order, 0)
                    #     order_flag, div_pc = analysis_operators_order(operator_order)
                    #     if order_flag:
                    #         global_problematic_pcs["operator_order_issue"].append(global_state["pc"])

                    #     # check_indivisible_amount(amount, path_conditions_and_vars, global_state, global_problematic_pcs)
                    #     from_param = path_conditions_and_vars["Ia"]
                    #     to = mem[argsOffset + 4]
                    #     add_token_flow(
                    #         token_address, from_param, to, amount, global_state
                    #     )
                    # else:
                    #     begin = argsOffset
                    #     end = argsOffset + argsSize
                    #     for index in mem:
                    #         if index >= begin and index < end:
                    #             amount = mem[index]
                    #             operator_order = get_expr_operators_order(var_to_operator, amount, operator_order, 0)
                    #             order_flag, div_pc = analysis_operators_order(operator_order)
                    #             if order_flag:
                    #                 global_problematic_pcs["operator_order_issue"].append(global_state["pc"])
                    #                 break

                    #             check_indivisible_amount(amount, path_conditions_and_vars, global_state, global_problematic_pcs)

                # use safeERC20
                # safeTransfer(IERC20 token, address to, uint256 value)
                elif (".safeTransfer" in source_code):
                    jump_target = stack[0]
                    value = stack[1]
                    to = stack[2]
                    token_address = stack[3]
                    from_param = path_conditions_and_vars["Ia"]

                    check_operator_order_issue(amount, global_state, global_problematic_pcs)

                    add_token_flow(
                        token_address, from_param, to, amount, global_state, path_conditions_and_vars, global_problematic_pcs
                    )                


    
    elif opcode == "CALL":
        source_code = ""
        if g_src_map:
            source_code = g_src_map.get_source_code(global_state["pc"])
            if source_code in g_src_map.func_call_names:
                # address.call{value: }("")
                if (".call" in source_code):
                    to = stack[1]
                    value = stack[2]

                    if (value == 0):
                        return

                    check_operator_order_issue(value, global_state, global_problematic_pcs)

                    check_indivisible_amount(value, path_conditions_and_vars, global_state, global_problematic_pcs, 0)
                    
                    from_param = path_conditions_and_vars["Ia"]
                    add_token_flow(
                        "ETH", from_param, to, value, global_state, path_conditions_and_vars, global_problematic_pcs
                    )
                
                # transferFrom(address from, address to, uint256 value)
                elif (".transferFrom" in source_code or ".safeTransfer" in source_code):
                    token_address = stack[1]
                    argsOffset = stack[3]
                    argsSize = stack[4]

                    if argsSize == 100:
                        if isReal(argsOffset):
                            amount = find_mem_real_info(mem_real, argsOffset + 4 + 32 + 32, 32)
                            from_param = find_mem_real_info(mem_real, argsOffset + 4, 32)
                            to = find_mem_real_info(mem_real, argsOffset + 4 + 32, 32)
                        else:
                            amount = mem[str(simplify(argsOffset + 4 + 32 + 32))]
                            from_param = mem[str(simplify(argsOffset + 4))]
                            to = mem[str(simplify(argsOffset + 4 + 32))]

                        check_operator_order_issue(amount, global_state, global_problematic_pcs)
                        # check_indivisible_amount(amount, path_conditions_and_vars, global_state, global_problematic_pcs)

                        add_token_flow(
                            token_address, from_param, to, amount, global_state, path_conditions_and_vars, global_problematic_pcs
                        )

                    else:

                        if isAllReal(argsOffset, argsSize):
                            temp_possible_amounts = find_mem_real_info_s(mem_real, argsOffset, argsSize)
                            for amount in temp_possible_amounts:
                                check_operator_order_issue(amount, global_state, global_problematic_pcs)
                        elif isReal(argsSize) and isSymbolic(argsOffset):
                            for i in range(argsSize):
                                index = simplify(argsOffset + i)
                                if (str(index) in mem):
                                    amount = mem[str(index)]
                                    check_operator_order_issue(amount, global_state, global_problematic_pcs)

                
                elif (".send(" in source_code):
                    to = stack[1]
                    value = stack[2]
                    from_param = path_conditions_and_vars["Ia"]

                    if (value == 0):
                        return

                    check_operator_order_issue(value, global_state, global_problematic_pcs)
                    check_indivisible_amount(value, path_conditions_and_vars, global_state, global_problematic_pcs, 0)
                    add_token_flow("ETH", from_param, to, value, global_state, path_conditions_and_vars, global_problematic_pcs)

                # transfer(address to, uint256 value) or <address payable>.transfer(uint256 amount)
                elif (".transfer" in source_code):
                    token_address = stack[1]
                    argsOffset = stack[3]
                    argsSize = stack[4]        
                    if argsSize == 68:

                        if isReal(argsOffset):
                            amount = find_mem_real_info(mem_real, argsOffset + 4 + 32, 32)
                            from_param = path_conditions_and_vars["Ia"]
                            to = find_mem_real_info(mem_real, argsOffset + 4, 32)
                        else:
                            amount = mem[str(simplify(argsOffset + 4 + 32))]
                            from_param = path_conditions_and_vars["Ia"]
                            to = mem[str(simplify(argsOffset + 4))]

                        check_operator_order_issue(amount, global_state, global_problematic_pcs)
                        
                        check_indivisible_amount(amount, path_conditions_and_vars, global_state, global_problematic_pcs, 1)
                        add_token_flow(
                            token_address, from_param, to, amount, global_state, path_conditions_and_vars, global_problematic_pcs
                        )
                    elif argsSize == 0:
                        to = stack[1]
                        value = stack[2]
                        from_param = path_conditions_and_vars["Ia"]

                        if (value == 0):
                            return

                        check_operator_order_issue(value, global_state, global_problematic_pcs)
                        check_indivisible_amount(value, path_conditions_and_vars, global_state, global_problematic_pcs, 0)
                        add_token_flow("ETH", from_param, to, value, global_state, path_conditions_and_vars, global_problematic_pcs)

                    else:
                        if isAllReal(argsOffset, argsSize):
                            temp_possible_amounts = find_mem_real_info_s(mem_real, argsOffset, argsSize)
                            for amount in temp_possible_amounts:
                                check_operator_order_issue(amount, global_state, global_problematic_pcs)
                        elif isReal(argsSize) and isSymbolic(argsOffset):
                            for i in range(argsSize):
                                index = simplify(argsOffset + i)
                                if (str(index) in mem):
                                    amount = mem[str(index)]
                                    check_operator_order_issue(amount, global_state, global_problematic_pcs)
                        # begin = argsOffset
                        # end = argsOffset + argsSize
                        # var_to_operator = global_state["var_to_operator"]
                        # for index in mem:
                        #     if index >= begin and index < end:
                        #         amount = mem[index]
                        #         operator_order = get_expr_operators_order(var_to_operator, amount, operator_order, 0)
                        #         order_flag, div_pc = analysis_operators_order(operator_order)
                        #         if order_flag:
                        #             global_problematic_pcs["operator_order_issue"].append(global_state["pc"])
                        #             break

                                # check_indivisible_amount(amount, path_conditions_and_vars, global_state, global_problematic_pcs)

    # elif opcode == "RETURN":
    #     offset = stack[0]
    #     size = stack[1]
    #     begin = offset
    #     end = offset + size
    #     params = g_src_map.func_name_to_return_params[current_func_name]
    #     for param in params:
    #         if param["param_type"].startwith("uint"):
    #             if isSymbolic(begin):
    #                 return_number = mem[str(simplify(begin + param["position"] * 32))]
    #                 check_operator_order_issue(return_number)
    #             else:
    #                 return_number = mem[begin + param["position"] * 32]
    #                 check_operator_order_issue(return_number)
    #         # check
                                    
    # elif opcode.startswith("LOG"):
    elif opcode == "LOG2":
        if g_src_map:
            source_code = g_src_map.get_source_code(global_state["pc"])
            if source_code in g_src_map.func_call_names:
                if source_code.startswith("Mint"):
                    # event Mint(address indexed to, uint256 amount);
                    offset = stack[0]
                    size = stack[1]
                    topic2_to = stack[3]
                    token = path_conditions_and_vars["Ia"]
                    value = None

                    if isReal(size) and size == 32:
                        if isReal(offset):
                            value = find_mem_real_info(mem_real, offset, 32)
                        else:
                            if (str(offset) in mem):
                                value = mem[str(offset)]

                    if value is not None:
                        check_operator_order_issue(value, global_state, global_problematic_pcs)
                        from_param = path_conditions_and_vars["Ia"]

                        add_token_flow(
                            token, from_param, topic2_to, value, global_state, path_conditions_and_vars, global_problematic_pcs
                        )

    elif opcode == "LOG3":                             
        if g_src_map:
            source_code = g_src_map.get_source_code(global_state["pc"])
            if source_code in g_src_map.func_call_names:
                if source_code.startswith("Transfer"):
                    # event Transfer(address indexed _from, address indexed _to, uint256 _value);
                    offset = stack[0]
                    size = stack[1]
                    topic2_from = stack[3]
                    topic3_to = stack[4]

                    token = path_conditions_and_vars["Ia"]
                    value = None
                    if isReal(size) and size == 32:
                        if isReal(offset):
                            value = find_mem_real_info(mem_real, offset, 32)
                        else:
                            if (str(offset) in mem):
                                value = mem[str(offset)]

                    if value is not None:
                        check_operator_order_issue(value, global_state, global_problematic_pcs)
                        if topic2_from == 0:
                            topic2_from = path_conditions_and_vars["Ia"]

                        add_token_flow(
                            token, topic2_from, topic3_to, value, global_state, path_conditions_and_vars, global_problematic_pcs
                        )

                    # length = int(opcode[3:])
                    # value_2 = stack[2 + length]
                    # if length == 1:
                    #     # event Transfer(address, address, uint256);
                    #     pass
                    # elif length == 3:
                    #     # event Transfer(address indexed from, address indexed to, uint256 value);
                    #     pass
                    # assert(value == value_2)

                
### 
def match_opcodes_sequence(block_ins, global_state, source_code):
    if not source_code:
        return
    if source_code.startswith("if"):
        if global_params.SOLC_VERSION.startswith("0.4"):
            if (
                block_ins[-2].startswith("PUSH")
                and block_ins[-3] == "ISZERO "
            ):
                if block_ins[-4] == "EQ ":
                    # if(a == b)
                    pass
                elif block_ins[-4] == "GT ":
                    # if(a > b)
                    global_state["conditional_statement"]["trigger"] = True
                    global_state["conditional_statement"]["comparison_type"] = "GT"
                    global_state["conditional_statement"]["statement_type"] = "if"
                elif block_ins[-4] == "LT ":
                    # if(a < b)
                    global_state["conditional_statement"]["trigger"] = True
                    global_state["conditional_statement"]["comparison_type"] = "LT"
                    global_state["conditional_statement"]["statement_type"] = "if"
                elif block_ins[-4] == "ISZERO ":
                    if block_ins[-5] == "LT ":
                        # if(a >= b)
                        global_state["conditional_statement"]["trigger"] = True
                        global_state["conditional_statement"]["comparison_type"] = "GT_and_EQ"
                        global_state["conditional_statement"]["statement_type"] = "if"
                    elif block_ins[-5] == "GT ":
                        # if(a <= b)
                        global_state["conditional_statement"]["trigger"] = True
                        global_state["conditional_statement"]["comparison_type"] = "LT_and_EQ"
                        global_state["conditional_statement"]["statement_type"] = "if"

        elif (
            global_params.SOLC_VERSION.startswith("0.5")
            or global_params.SOLC_VERSION.startswith("0.6")
            or global_params.SOLC_VERSION.startswith("0.7")
        ):
            if (
                block_ins[-2].startswith("PUSH")
            ):
                if block_ins[-3] == "ISZERO ":
                    if block_ins[-4] == "EQ ":
                        # if(a == b)
                        pass
                    elif block_ins[-4] == "GT ":
                        # if(a > b)
                        global_state["conditional_statement"]["trigger"] = True
                        global_state["conditional_statement"]["comparison_type"] = "GT"
                        global_state["conditional_statement"]["statement_type"] = "if"
                    elif block_ins[-4] == "LT ":
                        # if(a < b)
                        global_state["conditional_statement"]["trigger"] = True
                        global_state["conditional_statement"]["comparison_type"] = "LT"
                        global_state["conditional_statement"]["statement_type"] = "if"

                elif block_ins[-3] == "LT ":
                    # if(a >= b)
                    global_state["conditional_statement"]["trigger"] = True
                    global_state["conditional_statement"]["comparison_type"] = "GT_and_EQ"
                    global_state["conditional_statement"]["statement_type"] = "if"
                elif block_ins[-3] == "GT ":
                    # if(a <= b)
                    global_state["conditional_statement"]["trigger"] = True
                    global_state["conditional_statement"]["comparison_type"] = "LT_and_EQ"
                    global_state["conditional_statement"]["statement_type"] = "if"

        elif global_params.SOLC_VERSION.startswith("0.8"):
            if (
                block_ins[-2].startswith("PUSH")
            ):
                if block_ins[-3] == "SUB ":
                    # if(a == b)
                    pass
                elif block_ins[-3] == "ISZERO ":
                    if block_ins[-4] == "GT ":
                        # if(a > b)
                        global_state["conditional_statement"]["trigger"] = True
                        global_state["conditional_statement"]["statement_type"] = "if"
                        global_state["conditional_statement"]["comparison_type"] = "GT"
                    elif block_ins[-4] == "LT ":
                        # if(a < b)
                        global_state["conditional_statement"]["trigger"] = True
                        global_state["conditional_statement"]["statement_type"] = "if"
                        global_state["conditional_statement"]["comparison_type"] = "LT"

                elif block_ins[-3] == "LT ":
                    # if(a >= b)
                    global_state["conditional_statement"]["trigger"] = True
                    global_state["conditional_statement"]["statement_type"] = "if"
                    global_state["conditional_statement"]["comparison_type"] = "GT_and_EQ"
                elif block_ins[-3] == "GT ":
                    # if(a <= b)
                    global_state["conditional_statement"]["trigger"] = True
                    global_state["conditional_statement"]["statement_type"] = "if"
                    global_state["conditional_statement"]["comparison_type"] = "LT_and_EQ"

    elif source_code.startswith("require"):
        pass
    elif source_code.startswith("assert"):
        pass

def find_conditional_block(block_ins, global_state, g_src_map):
    if block_ins[-1] == "JUMPI ":
        if g_src_map:
            
            push_position = 0
            for ins in block_ins:
                if ins.startswith("PUSH"):
                    opcode = ins.split(" ")[0]
                    push_position += int(opcode[4:], 10)

            source_code = g_src_map.get_source_code(global_state["pc"] + len(block_ins) - 1 + push_position)

            match_opcodes_sequence(block_ins, global_state, source_code)

def reset_conditional_statement(global_state):
    if global_state["conditional_statement"]["trigger"] == True:
        global_state["conditional_statement"]["trigger"] = False
        global_state["conditional_statement"]["first"] = None
        global_state["conditional_statement"]["second"] = None
        global_state["conditional_statement"]["statement_type"] = None
        global_state["conditional_statement"]["comparison_type"] = None

def handle_comparison(global_state, first, second):
    if global_state["conditional_statement"]["trigger"] == True:
        # maybe there are two comparison in the block
        # if (
        #     "bvudiv_i" not in str(first) 
        #     and "bvudiv_i" not in str(second)
        # ):
        #     reset_conditional_statement(global_state)
        global_state["conditional_statement"]["first"] = first
        global_state["conditional_statement"]["second"] = second


def handle_first_and_second_result(first_result, second_result, depth):
    first_div_flag, first_check_res, first_depth = first_result
    second_div_flag, second_check_res, second_depth = second_result
    # first_div_flag means if meets a division
    # first_check_res means if exists div_in_path
    
    if first_div_flag == False and second_div_flag == False:
        return False, False, depth
    
    elif first_div_flag == True and second_div_flag == False:
        return first_div_flag, first_check_res, first_depth
    
    elif first_div_flag == False and second_div_flag == True:
        return second_div_flag, second_check_res, second_depth
    
    elif first_div_flag == True and second_div_flag == True:
        if first_depth < second_depth:
            return first_div_flag, first_check_res, first_depth
        elif first_depth > second_depth:
            return second_div_flag, second_check_res, second_depth
        elif first_depth == second_depth:
            return first_div_flag, (first_check_res or second_check_res), first_depth

    

def handle_GT_left(expr, var_to_operator, path_condition, depth):
    if depth == 5:
        return False, False, depth

    # var_to_operator = global_state["var_to_operator"]
    if expr not in var_to_operator:
        return False, False, depth
    first, operator, second, pc = var_to_operator[expr]
    if operator == "div":
        new_path_condition = []
        # new_path_condition.append(URem(first, second) != 0)
        new_path_condition.append(Not(URem(first, second) == 0))
        # path_condition = path_conditions_and_vars["path_condition"]
        
        solver = Solver()
        solver.set("timeout", global_params.TIMEOUT)
        solver.add(path_condition)
        solver.push()
        solver.add(new_path_condition)
        log.debug("[+] start to check div_in_path")
        ret = solver.check()
        # if ret == sat:
        #     log.info("[+] div_in_path exists")
        #     # global_problematic_pcs["div_in_path"].append(global_state["pc"])
        #     return True, True, depth
        # elif ret == unknown:
        #     log.info("[+]check unknown reason: " + solver.reason_unknown())
        # elif ret == unsat:
        #     log.info("[+] div_in_path does not exist")
        if ret == unsat:
            log.info("[+] div_in_path does not exist")
        else: # To be conservative
            log.info("[+] div_in_path exists")
            return True, True, depth
        
        return True, False, depth

    elif operator == "add" or operator == "mul":
        first_result = handle_GT_left(first, var_to_operator, path_condition, depth + 1)
        second_result = handle_GT_left(second, var_to_operator, path_condition, depth + 1)
        return handle_first_and_second_result(first_result, second_result, depth)

    elif operator == "sub":
        first_result = handle_GT_left(first, var_to_operator, path_condition, depth + 1)
        second_result = handle_GT_right(second, var_to_operator, path_condition, depth + 1)
        return handle_first_and_second_result(first_result, second_result, depth)

def handle_GT_right(expr, var_to_operator, path_condition, depth):
    return handle_LT_left(expr, var_to_operator, path_condition, depth)

def handle_LT_left(expr, var_to_operator, path_condition, depth):
    if depth == 5:
        return False, False, depth
    # var_to_operator = global_state["var_to_operator"]
    if expr not in var_to_operator:
        return False, False, depth
    first, operator, second, pc = var_to_operator[expr]
    if operator == "div":
        return True, False, depth
    elif operator == "add" or operator == "mul":
        first_result = handle_LT_left(first, var_to_operator, path_condition, depth + 1)
        second_result = handle_LT_left(second, var_to_operator, path_condition, depth + 1)
        return handle_first_and_second_result(first_result, second_result, depth)
    elif operator == "sub":
        first_result = handle_LT_left(first, var_to_operator, path_condition, depth + 1)
        second_result = handle_LT_right(second, var_to_operator, path_condition, depth + 1)
        return handle_first_and_second_result(first_result, second_result, depth)

def handle_LT_right(expr, var_to_operator, path_condition, depth):
    return handle_GT_left(expr, var_to_operator, path_condition, depth)


def handle_LT_and_EQ_left(expr, var_to_operator, path_condition, depth):
    if depth == 5:
        return False, False, depth
    
    # var_to_operator = global_state["var_to_operator"]
    if expr not in var_to_operator:
        return False, False, depth
    first, operator, second, pc = var_to_operator[expr]
    if operator == "div":
        new_path_condition = []
        # new_path_condition.append(URem(first, second) != 0)
        new_path_condition.append(Not(URem(first, second) == 0))
        # path_condition = path_conditions_and_vars["path_condition"]
        
        solver = Solver()
        solver.set("timeout", global_params.TIMEOUT)
        solver.add(path_condition)
        solver.push()
        solver.add(new_path_condition)
        log.debug("[+] start to check div_in_path")
        ret = solver.check()
        # if ret == sat:
        #     log.info("[+] div_in_path exists")
        #     # global_problematic_pcs["div_in_path"].append(global_state["pc"])
        #     return True, True, depth
        # elif ret == unknown:
        #     log.info("[+]check unknown reason: " + solver.reason_unknown())
        # elif ret == unsat:
        #     log.info("[+] div_in_path does not exist")
        if ret == unsat:
            log.info("[+] div_in_path does not exist")
        else: # To be conservative
            log.info("[+] div_in_path exists")
            # global_problematic_pcs["div_in_path"].append(global_state["pc"])
            return True, True, depth
        
        return True, False, depth
    
    elif operator == "add" or operator == "mul":
        first_result = handle_LT_and_EQ_left(first, var_to_operator, path_condition, depth + 1)
        second_result = handle_LT_and_EQ_left(second, var_to_operator, path_condition, depth + 1)
        return handle_first_and_second_result(first_result, second_result, depth)
    elif operator == "sub":
        first_result = handle_LT_and_EQ_left(first, var_to_operator, path_condition, depth + 1)
        second_result = handle_LT_and_EQ_right(second, var_to_operator, path_condition, depth + 1)
        return handle_first_and_second_result(first_result, second_result, depth)

def handle_LT_and_EQ_right(expr, var_to_operator, path_condition, depth):
    return handle_GT_and_EQ_left(expr, var_to_operator, path_condition, depth)

def handle_GT_and_EQ_left(expr, var_to_operator, path_condition, depth):
    if depth == 5:
        return False, False, depth
    # var_to_operator = global_state["var_to_operator"]
    if expr not in var_to_operator:
        return False, False, depth
    first, operator, second, pc = var_to_operator[expr]
    if operator == "div":
        return True, False, depth
    elif operator == "add" or operator == "mul":
        first_result = handle_GT_and_EQ_left(first, var_to_operator, path_condition, depth + 1)
        second_result = handle_GT_and_EQ_left(second, var_to_operator, path_condition, depth + 1)
        return handle_first_and_second_result(first_result, second_result, depth)
    elif operator == "sub":
        first_result = handle_GT_and_EQ_left(first, var_to_operator, path_condition, depth + 1)
        second_result = handle_GT_and_EQ_right(second, var_to_operator, path_condition, depth + 1)
        return handle_first_and_second_result(first_result, second_result, depth)

def handle_GT_and_EQ_right(expr, var_to_operator, path_condition, depth):
    return handle_LT_and_EQ_left(expr, var_to_operator, path_condition, depth)


def analysis_include_input_params(path_conditions_and_vars, first, second):
    input_params = path_conditions_and_vars["input"]
    if is_expr(first):
        first_list_vars = get_vars(first)
        for var in first_list_vars:
            if var in input_params:
                return True
    
    if is_expr(second):
        second_list_vars = get_vars(second)
        for var in second_list_vars:
            if var in input_params:
                return True
            
    return False

def check_div_in_path(branch_expression, global_state, global_problematic_pcs, g_src_map, path_conditions_and_vars):
    if not is_expr(branch_expression):
        reset_conditional_statement(global_state)
        return
    expr_str = str(branch_expression)
    if "bvudiv_i" not in expr_str:
        reset_conditional_statement(global_state)
        return
    
    pc_path = [x for x in global_state["func_jump_path"]]
    pc_path.append(global_state["pc"])
    if pc_path in global_problematic_pcs["div_in_path"]:
        reset_conditional_statement(global_state)
        return

    var_to_operator = global_state["var_to_operator"]
    path_condition = path_conditions_and_vars["path_condition"]

    if global_state["conditional_statement"]["trigger"] == True:
        first = global_state["conditional_statement"]["first"]
        second = global_state["conditional_statement"]["second"]

        input_flag = analysis_include_input_params(path_conditions_and_vars, first, second)
        if input_flag == False:
            reset_conditional_statement(global_state)
            return

        if global_state["conditional_statement"]["comparison_type"] == "GT":
            first_result = handle_GT_left(first, var_to_operator, path_condition, 0)
            second_result = handle_GT_right(second, var_to_operator, path_condition, 0)
            _, check_res, _ = handle_first_and_second_result(first_result, second_result, 0)
            if check_res:
                # global_problematic_pcs["div_in_path"].append(global_state["pc"])
                global_problematic_pcs["div_in_path"].append(pc_path)
            
        elif global_state["conditional_statement"]["comparison_type"] == "LT":
            first_result = handle_LT_left(first, var_to_operator, path_condition, 0)
            second_result = handle_LT_right(second, var_to_operator, path_condition, 0)
            _, check_res, _ = handle_first_and_second_result(first_result, second_result, 0)
            if check_res:
                # global_problematic_pcs["div_in_path"].append(global_state["pc"])
                global_problematic_pcs["div_in_path"].append(pc_path)
        elif global_state["conditional_statement"]["comparison_type"] == "GT_and_EQ":
            first_result = handle_GT_and_EQ_left(first, var_to_operator, path_condition, 0)
            second_result = handle_GT_and_EQ_right(second, var_to_operator, path_condition, 0)
            _, check_res, _ = handle_first_and_second_result(first_result, second_result, 0)
            if check_res:
                # global_problematic_pcs["div_in_path"].append(global_state["pc"])
                global_problematic_pcs["div_in_path"].append(pc_path)
        elif global_state["conditional_statement"]["comparison_type"] == "LT_and_EQ":
            first_result = handle_LT_and_EQ_left(first, var_to_operator, path_condition, 0)
            second_result = handle_LT_and_EQ_right(second, var_to_operator, path_condition, 0)
            _, check_res, _ = handle_first_and_second_result(first_result, second_result, 0)
            if check_res:
                # global_problematic_pcs["div_in_path"].append(global_state["pc"])
                global_problematic_pcs["div_in_path"].append(pc_path)

        reset_conditional_statement(global_state)

    # expr_str = str(branch_expression)

    # if "bvudiv_i" in expr_str:
    #     if g_src_map:
    #         source_code = g_src_map.get_source_code(global_state["pc"])
    #     global_problematic_pcs["div_in_path"].append(global_state["pc"])
        # source_code = ""
        # if g_src_map:
        #     source_code = g_src_map.get_source_code(global_state["pc"])
        #     if source_code in g_src_map.func_call_names:
        #         if (source_code.startswith("_safeMint") or source_code.startswith("safeTransferFrom")):
        #             global_problematic_pcs["div_in_path"].append(global_state["pc"])                

def check_operator_order_issue_with_mul(first, second, pc, global_state, global_problematic_pcs, g_src_map):
    pc_path = [x for x in global_state["func_jump_path"]]
    pc_path.append(pc)
    if pc_path in global_problematic_pcs["operator_order_issue"]:
        return
    
    var_to_operator = global_state["var_to_operator"]
    first_flag = analysis_operators_order_with_mul(first, var_to_operator, 0)
    second_flag = analysis_operators_order_with_mul(second, var_to_operator, 0)
    if (first_flag or second_flag):
        if g_src_map:
            source_code = g_src_map.get_source_code(pc)
            # when meet some statements such as "string public name", it will be filtered
            if ((source_code.startswith("string") or source_code.startswith("bytes")) and "public " in source_code):
                return
            # when meet some statements such as "function test(bytes _data) {}", it will be filtered
            if (source_code.startswith("function") and ("string" in source_code or "bytes" in source_code)):
                return
            # if (".call(" in source_code):
            #     return
            if (source_code.startswith("return")):
                return
            if global_params.SOLC_VERSION.startswith("0.4"):
                if filter_bytes_interception_operation(pc, g_src_map):
                    return

        # global_problematic_pcs["operator_order_issue"].append(global_state["pc"])
        log.debug("[+] operator_order_issue exists")
        global_problematic_pcs["operator_order_issue"].append(pc_path)

def filter_bytes_interception_operation(pc, g_src_map):
    # PUSH32 0x0100000000000000000000000000000000000000000000000000000000000000
    # SWAP1
    # DIV
    # PUSH32 0x0100000000000000000000000000000000000000000000000000000000000000
    # MUL
    filter_state = {
        "push_trigger": False, 
        "push_value": None, 
        "push_value_len": None, 
    }

    if g_src_map:
        i = -1
        instr_positions = g_src_map.instr_positions
        
        while True:
            i += 1
            index = pc - i
            if index not in instr_positions:
                continue
            if instr_positions[index]["name"] == "JUMPDEST" or index < 0:
                break
            elif instr_positions[index]["name"] == "PUSH" and filter_state["push_trigger"] == False:
                filter_state["push_trigger"] = True
                filter_state["push_value"] = instr_positions[index]["value"]
                filter_state["push_value_len"] = (len(instr_positions[index]["value"]) + 1) // 2
                if i != filter_state["push_value_len"] + 1:
                    break

            elif instr_positions[index]["name"] == "DIV" and filter_state["push_trigger"] == True:
                if instr_positions[index - 1]["name"] == "SWAP1":
                    end_push_index = index - 1 - 1 - filter_state["push_value_len"]
                    if (
                        end_push_index in instr_positions
                        and instr_positions[end_push_index]["name"] == "PUSH"
                        and instr_positions[end_push_index]["value"] == filter_state["push_value"]
                    ):
                        return True
            
        return False


def analysis_operators_order_with_mul(expr, var_to_operator, depth):
    if depth == 20:
        return False
    if expr not in var_to_operator:
        return False
    
    first, operator, second, pc = var_to_operator[expr]
    if operator == "div":
        return True
    else:
        first_flag = analysis_operators_order_with_mul(first, var_to_operator, depth + 1)
        second_flag = analysis_operators_order_with_mul(second, var_to_operator, depth + 1)
        return (first_flag or second_flag)



def check_operator_order_issue(expr, global_state, global_problematic_pcs):
    if not is_expr(expr):
        return
    pc_path = [x for x in global_state["func_jump_path"]]
    pc_path.append(global_state["pc"])
    if pc_path in global_problematic_pcs["operator_order_issue"]:
        return
    var_to_operator = global_state["var_to_operator"]
    root = Node("")
    build_operator_order_tree(expr, var_to_operator, 0, root)
    result = analysis_operator_order_tree(root, 0, False)
    if result:
        log.debug("[+] operator_order_issue exists")
        global_problematic_pcs["operator_order_issue"].append(pc_path)
    
def build_operator_order_tree(expr, var_to_operator, depth, node):
    if expr not in var_to_operator:
        return 
    if depth == 20:
        return 
    first, op, second, pc = var_to_operator[expr]
    if op == "exp":
        new_node = Node(op, parent=node, base=first)
    else:
        new_node = Node(op, parent=node)

    build_operator_order_tree(first, var_to_operator, depth + 1, new_node)
    build_operator_order_tree(second, var_to_operator, depth + 1, new_node)

def analysis_operator_order_tree(node, depth, mul_trigger):
    if depth == 20:
        return False
    result = False
    new_mul_trigger = mul_trigger
    if node.name == "mul":
        new_mul_trigger = True
    elif node.name == "div":
        if mul_trigger == True:
            if filter_exp(node):
                result = False
            else:
                result = True
    children = node.children
    if len(children) == 1:
        child1_result = analysis_operator_order_tree(children[0], depth + 1, new_mul_trigger)
        result = result or child1_result
    elif len(children) == 2:
        child1_result = analysis_operator_order_tree(children[0], depth + 1, new_mul_trigger)
        child2_result = analysis_operator_order_tree(children[1], depth + 1, new_mul_trigger)
        result = result or child1_result or child2_result
    return result

def filter_exp(node):
    current_node = node
    while current_node.name != "mul":
        current_node = current_node.parent
    
    children = current_node.children
    for child in children:
        if child.name == "exp" and child.base == 10:
            return True
    return False

# def check_operator_order_issue(expr, global_state, global_problematic_pcs):
#     if not is_expr(expr):
#         return
#     pc_path = [x for x in global_state["func_jump_path"]]
#     pc_path.append(global_state["pc"])
#     if pc_path in global_problematic_pcs["operator_order_issue"]:
#         return
#     operator_order = []
#     var_to_operator = global_state["var_to_operator"]
#     operator_order = get_expr_operators_order(var_to_operator, expr, operator_order, 0)
#     order_flag, mul_pc = analysis_operators_order(operator_order)
#     if order_flag:
#         # global_problematic_pcs["operator_order_issue"].append(mul_pc)
#         log.debug("[+] operator_order_issue exists")
#         global_problematic_pcs["operator_order_issue"].append(pc_path)


# def get_expr_operators_order(var_to_operator, expr, operator_order, depth):
#     # Get the operator of an expression recursively
#     if depth == 20:
#         return operator_order
#     if expr in var_to_operator:
#         first, operator, second, pc = var_to_operator[expr]
#         if depth == len(operator_order):
#             operator_order.append([])

#         if operator == "exp":
#             operator_order[depth].append([operator, pc, first])
#         else:
#             operator_order[depth].append([operator, pc])

#         operator_order = get_expr_operators_order(var_to_operator, first, operator_order, depth+1)
#         operator_order = get_expr_operators_order(var_to_operator, second, operator_order, depth+1)
    
#     return operator_order

# def analysis_operators_order(operator_order):
#     # Judge if div first and then mul
#     div_depth = -1
#     mul_pc = -1
#     mul_depth = -1

#     for depth in range(len(operator_order)):
#         for operator_with_pc in operator_order[depth]:
#             if operator_with_pc[0] == "div":
#                 div_depth = depth
                
#     if div_depth != -1:
#         # for depth in range(div_depth):
#         for depth in range(div_depth - 1, -1, -1):
#             for operator_with_pc in operator_order[depth]:
#                 if operator_with_pc[0] == "mul":
#                     mul_depth = depth
#                     mul_pc = operator_with_pc[1]
#                     break
#                     # return True, mul_pc
#             if mul_depth != -1:
#                 break
    
#     if mul_depth != -1:
#         # remove (a * 10^n / c) * b / 10^n
#         if (div_depth + 2) <= len(operator_order) - 1:
#             f1, f2 = False, False
#             for operator_with_pc in operator_order[div_depth + 1]:
#                 if operator_with_pc[0] == "mul":
#                     f1 = True
#                     break
#             for operator_with_pc in operator_order[div_depth + 2]:
#                 if operator_with_pc[0] == "exp":
#                     base = operator_with_pc[2]
#                     if base == 10:
#                         f2 = True
#                         break
#             if f1 and f2:
#                 return False, -1
        
#         # remove a / b * 10^n
#         for operator_with_pc in operator_order[mul_depth + 1]:
#             if operator_with_pc[0] == "exp":
#                 base = operator_with_pc[2]
#                 if base == 10:
#                     return False, -1
                
#         return True, mul_pc

#     return False, mul_pc


def check_indivisible_amount(amount, path_conditions_and_vars, global_state, global_problematic_pcs, token_type):
    if not is_expr(amount):
        return
    if (global_problematic_pcs["extract_all_eth"] == True and token_type == 0):
        return
    
    var_to_operator = global_state["var_to_operator"]
    if amount not in var_to_operator:
        return
    
    pc_path = [x for x in global_state["func_jump_path"]]
    pc_path.append(global_state["pc"])
    if pc_path in global_problematic_pcs["indivisible_amount"]:
        return
    
    first, operator, second, pc = var_to_operator[amount]
    if operator == "div":
        
        if isAllReal(first, second):
            # (URem(first, second) == 0)
            if first % second != 0:
                # global_problematic_pcs["indivisible_amount"].append(global_state["pc"])
                global_problematic_pcs["indivisible_amount"].append(pc_path)
        else:
            # URem(first, second) == 0
            new_path_condition = []
            # new_path_condition.append(URem(first, second) != 0)
            new_path_condition.append(Not(URem(first, second) == 0))
            path_condition = path_conditions_and_vars["path_condition"]

            # amount_list_vars = get_vars(amount)
            # path_condition = path_conditions_and_vars["path_condition"]
            # for expr in path_condition:
            #     if not is_expr(expr):
            #         continue
            #     list_vars = get_vars(expr)
            #     for var in list_vars:
            #         if var in amount_list_vars:
            #             new_path_condition.append(expr)
            #             break
            
            solver = Solver()
            solver.set("timeout", global_params.TIMEOUT)
            solver.add(path_condition)
            solver.push()
            solver.add(new_path_condition)
            log.debug("[+] start to check indivisible_amount")
            ret = solver.check()
            # log.debug("[+] check result is", ret)

            if ret == unsat:
                log.info("[+] indivisible_amount does not exist")
            else: # To be conservative
                log.info("[+] indivisible_amount exists")
                # global_problematic_pcs["indivisible_amount"].append(global_state["pc"])
                if token_type == 0:
                    global_problematic_pcs["indivisible_amount"].append(pc_path)
                else:
                    global_problematic_pcs["indivisible_amount_token"].append(pc_path)


def mask_address_var(var):
    if not isinstance(var, str) and isSymbolic(var):
        var = var & CONSTANT_ONES_159
        var = simplify(var) if is_expr(var) else var
    return var

def add_token_flow(token, from_param, to, amount, global_state, path_conditions_and_vars, global_problematic_pcs):

    token = mask_address_var(token)
    from_param = mask_address_var(from_param)
    to = mask_address_var(to)
    
    new_token_flow = {
        "token": token,
        "from": from_param,
        "to": to,
        "amount": amount
    }

    for token_flow in global_state["token_flow"]:
        if (
            str(token_flow["token"]) == str(token) 
            and token_flow["to"] == to 
            and token_flow["from"] == from_param
            and str(token_flow["amount"]) == str(amount)
        ):
            return

    global_state["token_flow"].append(new_token_flow)

    analysis_extract_all_eth(new_token_flow, global_state, path_conditions_and_vars, global_problematic_pcs)

    check_token_exchange_problem(token, from_param, to, amount, global_state, path_conditions_and_vars, global_problematic_pcs)
    check_precision_loss_trend(token, from_param, to, amount, global_state, path_conditions_and_vars, global_problematic_pcs)

def analysis_extract_all_eth(new_token_flow, global_state, path_conditions_and_vars, global_problematic_pcs):
    if (
        str(new_token_flow["token"]) == "ETH"
        and new_token_flow["from"] == mask_address_var(global_state["receiver_address"])
    ):
        if (str(new_token_flow["amount"]) == str(global_state["balance"]["Ia"])):
            global_problematic_pcs["extract_all_eth"] = True
            return
        
        if (new_token_flow["amount"] in path_conditions_and_vars["input"]):
            global_problematic_pcs["extract_all_eth"] = True
            return


    if (
        str(new_token_flow["token"]).startswith("Concat(0, Extract(159, 0, Ia_store-")
        and new_token_flow["from"] == mask_address_var(global_state["receiver_address"])
    ):
        if (new_token_flow["amount"] in path_conditions_and_vars["input"]):
            global_problematic_pcs["extract_all_token"] = True
            return


def check_precision_loss_trend(
        token, 
        from_param, 
        to, 
        amount, 
        global_state, 
        path_conditions_and_vars, 
        global_problematic_pcs
):
    var_to_operator = global_state["var_to_operator"]
    round_type, round_pc, _ = analysis_round_type(amount, var_to_operator, 0)
    if round_type != -1:
        if (from_param == mask_address_var(path_conditions_and_vars["Ia"])):
            if round_type == 2:
                pc_path = [x for x in global_state["func_jump_path"]]
                pc_path.append(global_state["pc"])
                global_problematic_pcs["precision_loss_trend"].append(pc_path)

        opposite_token_flows = find_opposite_token_flows(token, from_param, to, amount, global_state)
        if len(opposite_token_flows) == 0:
            return 
        for opposite_token_flow in opposite_token_flows:
            opposite_round_type, opposite_round_pc, _ = analysis_round_type(opposite_token_flow["amount"], var_to_operator, 0)
            if (round_type != -1 and opposite_round_type != -1):
                
                if (round_type == 1 and opposite_round_type == 1):
                    # global_problematic_pcs["precision_loss_trend"].append(opposite_round_pc)
                    pc_path = [x for x in global_state["func_jump_path"]]
                    pc_path.append(global_state["pc"])
                    global_problematic_pcs["precision_loss_trend"].append(pc_path)


    # var_to_operator = global_state["var_to_operator"]
    # opposite_token_flows = find_opposite_token_flows(token, from_param, to, amount, global_state)
    # if len(opposite_token_flows) == 0:
    #     return 
    # round_type, round_pc, _ = analysis_round_type(amount, var_to_operator, 0)
    
    # if round_type != -1:
    #     if (
    #         from_param == mask_address_var(path_conditions_and_vars["Ia"]) 
    #         # and to == mask_address_var(path_conditions_and_vars["Is"])
    #     ): # contract => sender
    #         if round_type == 2:
    #             # global_problematic_pcs["precision_loss_trend"].append(round_pc)
    #             pc_path = [x for x in global_state["func_jump_path"]]
    #             pc_path.append(global_state["pc"])
    #             global_problematic_pcs["precision_loss_trend"].append(pc_path)

    #     elif (
    #         # from_param == mask_address_var(path_conditions_and_vars["Is"])
    #         # and to == mask_address_var(path_conditions_and_vars["Ia"] )
    #         to == mask_address_var(path_conditions_and_vars["Ia"] )
    #     ): # sender => contract
    #         for opposite_token_flow in opposite_token_flows:
    #             opposite_round_type, opposite_round_pc, _ = analysis_round_type(opposite_token_flow["amount"], var_to_operator, 0)
    #             if opposite_round_type == 2:
    #                 # global_problematic_pcs["precision_loss_trend"].append(opposite_round_pc)
    #                 pc_path = [x for x in global_state["func_jump_path"]]
    #                 pc_path.append(global_state["pc"])
    #                 global_problematic_pcs["precision_loss_trend"].append(pc_path)
                

    # for opposite_token_flow in opposite_token_flows:
    #     opposite_round_type, opposite_round_pc, _ = analysis_round_type(opposite_token_flow["amount"], var_to_operator, 0)
    #     if (round_type != -1 and opposite_round_type != -1):
            
    #         if (round_type == 1 and opposite_round_type == 1):
    #             # global_problematic_pcs["precision_loss_trend"].append(opposite_round_pc)
    #             pc_path = [x for x in global_state["func_jump_path"]]
    #             pc_path.append(global_state["pc"])
    #             global_problematic_pcs["precision_loss_trend"].append(pc_path)

    

def find_opposite_token_flows(
        token, 
        from_param, 
        to, 
        amount,
        global_state
):
    opposite_token_flows = []
    token_flows = global_state["token_flow"]
    for token_flow in token_flows:
        if (
            token_flow["from"] == to 
            and token_flow["to"] == from_param 
            and str(token_flow["token"]) != str(token)
        ):
            exchange_flag = analysis_amount_relationship(amount, token_flow["amount"])
            if exchange_flag:
                opposite_token_flows.append(token_flow)

    return opposite_token_flows
    

def analysis_round_type(amount, var_to_operator, depth):
    if depth == 20:
        return -1, -1, depth
    if amount not in var_to_operator:
        return -1, -1, depth
    first, operator, second, pc = var_to_operator[amount]
    
    if operator == "div":
        round_type, round_pc = analysis_amount_round_type(amount, var_to_operator)
        return round_type, round_pc, depth
    elif operator == "add" or operator == "mul":
        first_round_type, first_round_pc, first_round_depth = analysis_round_type(first, var_to_operator, depth+1)
        second_round_type, second_round_pc, second_round_depth = analysis_round_type(second, var_to_operator, depth+1)
        if first_round_type != -1 and second_round_type == -1:
            round_type = first_round_type
            round_pc = first_round_pc
        elif first_round_type == -1 and second_round_type != -1:
            round_type = second_round_type
            round_pc = second_round_pc
        elif first_round_type != -1 and second_round_type != -1:
            if first_round_depth <= second_round_depth:
                round_type = first_round_type
                round_pc = first_round_pc
            else:
                round_type = second_round_type
                round_pc = second_round_pc
        else: # all -1
            return -1, -1, depth

        return round_type, round_pc, depth
    
    elif operator == "sub":
        first_round_type, first_round_pc, first_round_depth = analysis_round_type(first, var_to_operator, depth+1)
        second_round_type, second_round_pc, second_round_depth = analysis_round_type(second, var_to_operator, depth+1)
        if first_round_type != -1 and second_round_type == -1:
            round_type = first_round_type
            round_pc = first_round_pc
        elif first_round_type == -1 and second_round_type != -1:
            round_type = 2 - second_round_type
            round_pc = second_round_pc
        elif first_round_type != -1 and second_round_type != -1:
            if first_round_depth <= second_round_depth:
                round_type = first_round_type
                round_pc = first_round_pc
            else:
                round_type = 2 - second_round_type
                round_pc = second_round_pc
        else: # all -1
            return -1, -1, depth
        
        return round_type, round_pc, depth


def analysis_amount_round_type(amount, var_to_operator):

    dividend, operator, divisor, pc = var_to_operator[amount]
    # if operator == "div":
    # dividend = first
    # divisor = second
    if dividend not in var_to_operator:
        return -1, -1

    first, operator, second, pc = var_to_operator[dividend]
    if operator == "add":
        rounded_num_up = divisor - 1
        rounded_num_up = simplify(rounded_num_up) if is_expr(rounded_num_up) else rounded_num_up
        
        rounded_num = UDiv(divisor, 2)
        rounded_num = simplify(rounded_num) if is_expr(rounded_num) else rounded_num

        if second == rounded_num_up or first == rounded_num_up:
            log.debug("Rounded up")
            round_type = 2
            round_pc = pc
        elif second == rounded_num or first == rounded_num:
            log.debug("Rounding")
            round_type = 1
            round_pc = pc
        else:
            log.debug("no Rounded down")
            round_type = 0
            round_pc = pc
    else:
        log.debug("Rounded down")
        round_type = 0
        round_pc = pc
        
    return round_type, round_pc


def check_token_exchange_problem(
        token, 
        from_param, 
        to, 
        amount, 
        global_state, 
        path_conditions_and_vars, 
        global_problematic_pcs
):
    token_flows = global_state["token_flow"]
    for token_flow in token_flows:
        if (
            (token_flow["from"] == to) 
            and (token_flow["to"] == from_param or str(from_param).startswith("Concat(0, Extract(159, 0, Ia_store-")) 
            and (str(token_flow["token"]) != str(token))
        ):
            exchange_flag = analysis_amount_relationship(amount, token_flow["amount"])
            if exchange_flag:
                analysis_exchange_problem(
                    from_param, 
                    to, 
                    amount, 
                    token_flow["amount"], 
                    global_state, 
                    path_conditions_and_vars, 
                    global_problematic_pcs
                )


def analysis_amount_relationship(amount1, amount2):
    # if amount1 and amount2 have same vars, which means maybe token exchange exists
    if is_expr(amount1) and is_expr(amount2):
        amount1_list_vars = get_vars(amount1)
        amount2_list_vars = get_vars(amount2)
        for var in amount1_list_vars:
            if var in amount2_list_vars:
                return True
    return False
    

def analysis_exchange_problem(
        from_param, 
        to, 
        amount1, 
        amount2, 
        global_state, 
        path_conditions_and_vars, 
        global_problematic_pcs
):
    # pc_path = [x for x in global_state["func_jump_path"]]
    # pc_path.append(global_state["pc"])
    # if pc_path in global_problematic_pcs["exchange_problem"]:
    #     return
    
    if from_param == mask_address_var(path_conditions_and_vars["Is"]):
        amount_in = amount1
        amount_out = amount2

    elif to == mask_address_var(path_conditions_and_vars["Is"]):
        amount_in = amount2
        amount_out = amount1
    
    else:
        path_condition = path_conditions_and_vars["path_condition"]
        new_path_condition = []
        new_path_condition.append(amount1 != 0)
        new_path_condition.append(amount2 == 0)
        solver = Solver()
        solver.set("timeout", global_params.CHECK_TIMEOUT)
        solver.add(path_condition)
        solver.push()
        solver.add(new_path_condition)

        log.debug("[+] start to check exchange_problem")
        ret = solver.check()
        if ret == sat:
            # global_problematic_pcs["exchange_problem"].append(global_state["pc"])
            log.debug("[+] exchange_problem exists")
            pc_path = [x for x in global_state["func_jump_path"]]
            pc_path.append(global_state["pc"])
            global_problematic_pcs["exchange_problem"].append(pc_path)
        elif ret == unknown:
            log.info("[+]check timeout" + solver.reason_unknown())
        solver.pop()
        

        new_path_condition = []
        new_path_condition.append(amount1 == 0)
        new_path_condition.append(amount2 != 0)
        solver.push()
        solver.add(new_path_condition)

        log.debug("[+] start to check exchange_problem")
        ret = solver.check()
        if ret == sat:
            # global_problematic_pcs["exchange_problem"].append(global_state["pc"])
            log.debug("[+] exchange_problem exists")
            pc_path = [x for x in global_state["func_jump_path"]]
            pc_path.append(global_state["pc"])
            global_problematic_pcs["exchange_problem"].append(pc_path)
        elif(ret == unknown):
            log.info("[+]check timeout" + solver.reason_unknown())

        return 
        

    path_condition = path_conditions_and_vars["path_condition"]
    new_path_condition = []
    new_path_condition.append(amount_in != 0)
    new_path_condition.append(amount_out == 0)
    solver = Solver()
    solver.set("timeout", global_params.CHECK_TIMEOUT)
    solver.add(path_condition)
    solver.push()
    solver.add(new_path_condition)

    log.debug("[+] start to check exchange_problem, exchange_rounding")
    ret = solver.check()
    if ret == sat:
        # global_problematic_pcs["exchange_problem"].append(global_state["pc"])
        # global_problematic_pcs["exchange_rounding"].append(global_state["pc"])
        log.debug("[+] exchange_rounding exists")
        pc_path = [x for x in global_state["func_jump_path"]]
        pc_path.append(global_state["pc"])
        global_problematic_pcs["exchange_problem"].append(pc_path)
        global_problematic_pcs["exchange_rounding"].append(pc_path)
    elif ret == unknown:
        log.info("[+]check timeout" + solver.reason_unknown())
    solver.pop()
    

    new_path_condition = []
    new_path_condition.append(amount_in == 0)
    new_path_condition.append(amount_out != 0)
    solver.push()
    solver.add(new_path_condition)

    log.debug("[+] start to check exchange_problem, profit_opportunity")
    ret = solver.check()
    if ret == sat:
        # global_problematic_pcs["exchange_problem"].append(global_state["pc"])
        # global_problematic_pcs["profit_opportunity"].append(global_state["pc"])
        log.debug("[+] profit_opportunity exists")
        pc_path = [x for x in global_state["func_jump_path"]]
        pc_path.append(global_state["pc"])
        global_problematic_pcs["exchange_problem"].append(pc_path)
        global_problematic_pcs["profit_opportunity"].append(pc_path)
    elif(ret == unknown):
        log.info("[+]check timeout" + solver.reason_unknown())



