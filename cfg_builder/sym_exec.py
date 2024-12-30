import errno
import pickle
import signal
import time
import tokenize
import traceback
import hashlib
from collections import namedtuple
from tokenize import NUMBER, NAME, NEWLINE

from numpy import mod
from defect_identifier.defect import *
from defect_identifier.identifier import Identifier

from feature_detector.semantic_analysis import *
from cfg_builder.basicblock import BasicBlock
from cfg_builder.execution_states import UNKNOWN_INSTRUCTION, EXCEPTION, PICKLE_PATH
from cfg_builder.vargenerator import *
from cfg_builder.utils import *
from rich.table import Table
from rich.console import Console
from rich.live import Live

# Initiate table for live print.
console = Console()
table = Table()
live = Live(table, console=console, vertical_overflow="crop", auto_refresh=False)

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

# Store visited blocks
visited_blocks = set()

UNSIGNED_BOUND_NUMBER = 2**256 - 1
CONSTANT_ONES_159 = BitVecVal((1 << 160) - 1, 256)


def dynamic_defect_identification(g_src_map, global_problematic_pcs):
    """Find defects during execution

    Args:
        g_src_map (_type_): source map
        global_problematic_pcs (_type_): defects pcs

    Returns:
        defects: defects detection results during execution
    """
    public_burn = PublicBurnDefect(g_src_map, global_problematic_pcs["burn_defect"])
    unlimited_minting = UnlimitedMintingDefect(
        g_src_map, global_problematic_pcs["unlimited_minting_defect"]
    )
    proxy = RiskyProxyDefect(g_src_map, global_problematic_pcs["proxy_defect"])
    reentrancy = ReentrancyDefect(
        g_src_map, global_problematic_pcs["reentrancy_defect"]
    )
    violation = ViolationDefect(g_src_map, global_problematic_pcs["violation_defect"])
    return proxy, reentrancy, unlimited_minting, violation, public_burn


def generate_table(
    opcode, block_cov, pc, perc, g_src_map, global_problematic_pcs, current_func_name
) -> Table:
    (
        proxy,
        reentrancy,
        unlimited_minting,
        violation,
        public_burn,
    ) = dynamic_defect_identification(g_src_map, global_problematic_pcs)
    """Make a new table for live presentation

    Returns:
        table: table for live show
    """
    defect_table = Table()

    defect_table.add_column("Defect", justify="right", style="dim", no_wrap=True)
    defect_table.add_column("Status", style="green")
    defect_table.add_column("Location", justify="left", style="cyan")

    defect_table.add_row("Risky Mutable Proxy", str(proxy.is_defective()), str(proxy))
    defect_table.add_row(
        "ERC-721 Reentrancy", str(reentrancy.is_defective()), str(reentrancy)
    )
    defect_table.add_row(
        "Unlimited Minting",
        str(unlimited_minting.is_defective()),
        str(unlimited_minting),
    )
    defect_table.add_row(
        "Missing Requirements", str(violation.is_defective()), str(violation)
    )
    defect_table.add_row(
        "Public Burn", str(public_burn.is_defective()), str(public_burn)
    )
    end = time.time()

    time_coverage_table = Table()
    time_coverage_table.add_column(
        "Time", justify="left", style="cyan", no_wrap=True, width=8
    )
    time_coverage_table.add_column(
        "Code Coverage", justify="left", style="yellow", no_wrap=True
    )
    time_coverage_table.add_column(
        "Block Coverage", justify="left", style="yellow", no_wrap=True
    )
    time_coverage_table.add_row(
        str(round(end - begin, 1)), str(round(perc, 1)), str(round(block_cov, 1))
    )

    block_table = Table()
    block_table.add_column("PC", justify="left", style="cyan", no_wrap=True, width=8)
    block_table.add_column(
        "Opcode", justify="left", style="yellow", no_wrap=True, width=8
    )
    block_table.add_column(
        "Current Function", justify="left", style="yellow", no_wrap=True, min_width=19
    )

    block_table.add_row(str(pc), opcode, current_func_name)

    state_table = Table.grid(expand=True)
    state_table.add_column(justify="center")
    state_table.add_row(time_coverage_table)
    state_table.add_row(block_table)

    reporter = Table(title="NFTGuard GENESIS v0.0.1")
    reporter.add_column("Defect Detection", justify="center")
    reporter.add_column("Execution States", justify="center")
    reporter.add_row(defect_table, state_table)
    return reporter


class Parameter:
    def __init__(self, **kwargs):
        attr_defaults = {
            "stack": [],
            "visited": [],
            "mem": {},
            "mem_real": [],
            "sha3_list": {},
            "global_state": {},
            "path_conditions_and_vars": {},
        }
        for attr, default in six.iteritems(attr_defaults):
            setattr(self, attr, kwargs.get(attr, default))

    def copy(self):
        _kwargs = custom_deepcopy(self.__dict__)
        return Parameter(**_kwargs)


def initGlobalVars():
    # Initialize global variables
    global g_src_map
    global solver
    # Z3 solver
    solver = Solver()
    solver.set("timeout", global_params.TIMEOUT)
    # set_option(timeout=3000)

    global MSIZE
    MSIZE = False

    global g_disasm_file
    with open(g_disasm_file, "r") as f:
        disasm = f.read()
    if "MSIZE" in disasm:
        MSIZE = True

    global g_timeout
    g_timeout = False

    global visited_pcs
    visited_pcs = set()

    global results
    if g_src_map:
        global start_block_to_func_sig
        start_block_to_func_sig = {}

        results = {
            "evm_code_coverage": "",
            "instructions": "",
            "time": "",
            "analysis": {
                "div_in_path": [],
                "operator_order_issue": [],
                "indivisible_amount": [],
                "precision_loss_trend": [],
                "exchange_problem": [],
                "exchange_rounding": [],
                "profit_opportunity": [],

            },
            "bool_defect": {
                "div_in_path": False,
                "operator_order_issue": False,
                "indivisible_amount": False,
                "precision_loss_trend": False,
                "exchange_problem": False,
                "exchange_rounding": False,
                "profit_opportunity": False,
            },
        }
    else:
        results = {
            "evm_code_coverage": "",
            "instructions": "",
            "time": "",
            "bool_defect": {
                "div_in_path": False,
                "operator_order_issue": False,
                "indivisible_amount": False,
                "precision_loss_trend": False,
                "exchange_problem": False,
                "exchange_rounding": False,
                "profit_opportunity": False,
            },
        }

    # capturing the last statement of each basic block
    global end_ins_dict
    end_ins_dict = {}

    # capturing all the instructions, keys are corresponding addresses
    global instructions
    instructions = {}

    # capturing the "jump type" of each basic block
    global jump_type
    jump_type = {}

    global vertices
    vertices = {}

    global edges
    edges = {}

    # start: end
    global blocks
    blocks = {}

    global visited_edges
    visited_edges = {}

    global global_problematic_pcs  # for different defects
    global_problematic_pcs = {
        "div_in_path": [],
        "operator_order_issue": [],
        "indivisible_amount": [],
        "precision_loss_trend": [],
        "exchange_problem": [],
        "exchange_rounding": [],
        "profit_opportunity": [],

        "indivisible_amount_token": [],

        "extract_all_eth": False,
        "extract_all_token": False, # todo: More than one token
    }

    # store global variables, e.g. storage, balance of all paths
    global all_gs
    all_gs = []

    global total_no_of_paths
    total_no_of_paths = 0

    global no_of_test_cases
    no_of_test_cases = 0

    # to generate names for symbolic variables
    global gen
    gen = Generator()

    global rfile
    if global_params.REPORT_MODE:
        rfile = open(g_disasm_file + ".report", "w")

    global pruned_function
    pruned_function = load_pruning_file(global_params.PRUNING_FILE)

def load_pruning_file(pruning_file_path):
    if pruning_file_path == "":
        return []
    with open(pruning_file_path, "r", encoding="utf-8") as f:
        content = f.read().strip()

    try:
        pruning_res = json.loads(content)
    except:
        pruning_res = re.findall(r"(\{[\w\W]*?\})", content)[0]
        # res = json.loads(res)
        pruning_res = eval(pruning_res)
    
    related_functions = pruning_res["related"]
    unrelated_functions = pruning_res["unrelated"]
    return related_functions

def is_testing_evm():
    return global_params.UNIT_TEST != 0


def compare_storage_and_gas_unit_test(global_state, analysis):
    unit_test = pickle.load(open(PICKLE_PATH, "rb"))
    test_status = unit_test.compare_with_symExec_result(global_state, analysis)
    exit(test_status)


def change_format():
    """Change format for tokenization and buildng CFG"""
    with open(g_disasm_file) as disasm_file:
        file_contents = disasm_file.readlines()
        i = 0
        firstLine = file_contents[0].strip("\n")
        for line in file_contents:
            line = line.replace(":", "")
            lineParts = line.split(" ")
            try:  # removing initial zeroes
                lineParts[0] = str(int(lineParts[0], 16))

            except:
                lineParts[0] = lineParts[0]
            lineParts[-1] = lineParts[-1].strip("\n")
            try:  # adding arrow if last is a number
                lastInt = lineParts[-1]
                if (int(lastInt, 16) or int(lastInt, 16) == 0) and len(lineParts) > 2:
                    lineParts[-1] = "=>"
                    lineParts.append(lastInt)
            except Exception:
                pass
            file_contents[i] = " ".join(lineParts)
            i = i + 1
        file_contents[0] = firstLine
        file_contents[-1] += "\n"

    with open(g_disasm_file, "w") as disasm_file:
        disasm_file.write("\n".join(file_contents))


def build_cfg_and_analyze():
    """Build cfg and perform symbolic execution"""
    change_format()
    logging.info("Building CFG...")
    with open(g_disasm_file, "r") as disasm_file:
        disasm_file.readline()  # Remove first line
        tokens = tokenize.generate_tokens(disasm_file.readline)  # tokenization
        collect_vertices(tokens)  # find vertices
        construct_bb()
        construct_static_edges()  # find static edges from stack top
        full_sym_exec()  # jump targets are constructed on the fly


def print_cfg():
    for block in vertices.values():
        block.display()
    log.debug(str(edges))


def mapping_push_instruction(
    current_line_content, current_ins_address, idx, positions, length
):
    global g_src_map
    while idx < length:
        if not positions[idx]:
            return idx + 1
        name = positions[idx]["name"]
        if name.startswith("tag"):
            idx += 1
        else:
            if name.startswith("PUSH"):
                if name == "PUSH":
                    value = positions[idx]["value"]
                    instr_value = current_line_content.split(" ")[1]
                    if int(value, 16) == int(instr_value, 16):
                        g_src_map.instr_positions[
                            current_ins_address
                        ] = g_src_map.positions[idx]
                        idx += 1
                        break
                    else:
                        raise Exception("Source map error")
                else:
                    g_src_map.instr_positions[
                        current_ins_address
                    ] = g_src_map.positions[idx]
                    idx += 1
                    break
            else:
                raise Exception("Source map error")
    return idx


def mapping_non_push_instruction(
    current_line_content, current_ins_address, idx, positions, length
):
    global g_src_map
    while idx < length:
        if not positions[idx]:
            return idx + 1
        name = positions[idx]["name"]
        if name.startswith("tag"):
            idx += 1
        else:
            instr_name = current_line_content.split(" ")[0]
            if (
                name == instr_name
                or name == "INVALID"
                and instr_name == "ASSERTFAIL"
                or name == "KECCAK256"
                and instr_name == "SHA3"
                or name == "SELFDESTRUCT"
                and instr_name == "SUICIDE"
            ):
                g_src_map.instr_positions[current_ins_address] = g_src_map.positions[
                    idx
                ]
                idx += 1
                break
            else:
                raise RuntimeError(
                    f"Source map error, unknown name({name}) or instr_name({instr_name})"
                )
    return idx


# 1. Parse the disassembled file
# 2. Then identify each basic block (i.e. one-in, one-out)
# 3. Store them in vertices


def collect_vertices(tokens):
    global g_src_map
    if g_src_map:
        idx = 0
        positions = g_src_map.positions
        length = len(positions)
    global end_ins_dict
    global instructions
    global jump_type

    current_ins_address = 0
    last_ins_address = 0
    is_new_line = True
    current_block = 0
    current_line_content = ""
    wait_for_push = False
    is_new_block = False

    for tok_type, tok_string, (srow, scol), _, line_number in tokens:
        if wait_for_push is True:
            push_val = ""
            for ptok_type, ptok_string, _, _, _ in tokens:
                if ptok_type == NEWLINE:
                    is_new_line = True
                    current_line_content += push_val + " "
                    instructions[current_ins_address] = current_line_content
                    idx = (
                        mapping_push_instruction(
                            current_line_content,
                            current_ins_address,
                            idx,
                            positions,
                            length,
                        )
                        if g_src_map
                        else None
                    )
                    log.debug(current_line_content)
                    current_line_content = ""
                    wait_for_push = False
                    break
                try:
                    int(ptok_string, 16)
                    push_val += ptok_string
                except ValueError:
                    pass

            continue
        elif is_new_line is True and tok_type == NUMBER:  # looking for a line number
            last_ins_address = current_ins_address
            try:
                current_ins_address = int(tok_string)
            except ValueError:
                log.critical("ERROR when parsing row %d col %d", srow, scol)
                quit()
            is_new_line = False
            if is_new_block:
                current_block = current_ins_address
                is_new_block = False
            continue
        elif tok_type == NEWLINE:
            is_new_line = True
            log.debug(current_line_content)
            instructions[current_ins_address] = current_line_content
            idx = (
                mapping_non_push_instruction(
                    current_line_content, current_ins_address, idx, positions, length
                )
                if g_src_map
                else None
            )
            current_line_content = ""
            continue
        elif tok_type == NAME:
            if tok_string == "JUMPDEST":
                if last_ins_address not in end_ins_dict:
                    end_ins_dict[current_block] = last_ins_address
                current_block = current_ins_address
                is_new_block = False
            elif (
                tok_string == "STOP"
                or tok_string == "RETURN"
                or tok_string == "SUICIDE"
                or tok_string == "REVERT"
                or tok_string == "ASSERTFAIL"
                or tok_string == "INVALID"
            ):
                jump_type[current_block] = "terminal"
                end_ins_dict[current_block] = current_ins_address
            elif tok_string == "JUMP":
                jump_type[current_block] = "unconditional"
                end_ins_dict[current_block] = current_ins_address
                is_new_block = True
            elif tok_string == "JUMPI":
                jump_type[current_block] = "conditional"
                end_ins_dict[current_block] = current_ins_address
                is_new_block = True
            elif tok_string.startswith("PUSH", 0):
                wait_for_push = True
            is_new_line = False
        if tok_string != "=" and tok_string != ">":
            current_line_content += tok_string + " "

    if current_block not in end_ins_dict:
        log.debug("current block: %d", current_block)
        log.debug("last line: %d", current_ins_address)
        end_ins_dict[current_block] = current_ins_address

    if current_block not in jump_type:
        jump_type[current_block] = "terminal"

    for key in end_ins_dict: # for (from JUMPDEST to JUMPDEST) block
        if key not in jump_type:
            jump_type[key] = "falls_to"


def construct_bb():
    global vertices
    global edges
    global blocks
    sorted_addresses = sorted(instructions.keys())
    size = len(sorted_addresses)
    # logging.info("instruction size: %d" % size)
    for key in end_ins_dict:
        end_address = end_ins_dict[key]
        block = BasicBlock(key, end_address)
        if key not in instructions:
            continue
        block.add_instruction(instructions[key])
        i = sorted_addresses.index(key) + 1
        while i < size and sorted_addresses[i] <= end_address:
            block.add_instruction(instructions[sorted_addresses[i]])
            i += 1
        block.set_block_type(jump_type[key])
        vertices[key] = block
        blocks[key] = end_address
        edges[key] = []


def construct_static_edges():
    add_falls_to()  # these edges are static


def add_falls_to():
    global vertices
    global edges
    key_list = sorted(jump_type.keys())
    length = len(key_list)
    for i, key in enumerate(key_list):
        if (
            jump_type[key] != "terminal"
            and jump_type[key] != "unconditional"
            and i + 1 < length
        ):
            target = key_list[i + 1]
            edges[key].append(target)
            vertices[key].set_falls_to(target)


def get_init_global_state(path_conditions_and_vars):
    global_state = {"balance": {}, "pc": 0}
    init_is = (
        init_ia
    ) = (
        deposited_value
    ) = (
        sender_address
    ) = (
        receiver_address
    ) = (
        gas_price
    ) = (
        origin
    ) = (
        currentCoinbase
    ) = (
        currentNumber
    ) = (
        currentDifficulty
    ) = (
        currentGasLimit
    ) = currentChainId = currentSelfBalance = currentBaseFee = callData = currentTimestamp = None

    # init_is = init_ia = deposited_value = sender_address = receiver_address = gas_price = origin = currentCoinbase = currentNumber = currentDifficulty = currentGasLimit = 

    sender_address = BitVec("Is", 256)
    receiver_address = BitVec("Ia", 256)
    deposited_value = BitVec("Iv", 256)
    init_is = BitVec("init_Is", 256)
    init_ia = BitVec("init_Ia", 256)

    path_conditions_and_vars["Is"] = sender_address
    path_conditions_and_vars["Ia"] = receiver_address
    path_conditions_and_vars["Iv"] = deposited_value

    # from s to a, s is sender, a is receiver
    # v is the amount of ether deposited and transferred
    constraint = deposited_value >= BitVecVal(0, 256)
    path_conditions_and_vars["path_condition"].append(constraint)
    constraint = init_is >= deposited_value
    path_conditions_and_vars["path_condition"].append(constraint)
    constraint = init_ia >= BitVecVal(0, 256)
    path_conditions_and_vars["path_condition"].append(constraint)

    # update the balances of the "caller" and "callee"
    global_state["balance"]["Is"] = init_is - deposited_value
    global_state["balance"]["Ia"] = init_ia + deposited_value

    global_state["balance"][str(mask_address_var(sender_address))] = init_is - deposited_value
    global_state["balance"][str(mask_address_var(receiver_address))] = init_ia + deposited_value

    if not gas_price:
        new_var_name = gen.gen_gas_price_var()
        gas_price = BitVec(new_var_name, 256)
        path_conditions_and_vars[new_var_name] = gas_price

    if not origin:
        new_var_name = gen.gen_origin_var()
        origin = BitVec(new_var_name, 256)
        path_conditions_and_vars[new_var_name] = origin

    if not currentCoinbase:
        new_var_name = "IH_c"
        currentCoinbase = BitVec(new_var_name, 256)
        path_conditions_and_vars[new_var_name] = currentCoinbase

    if not currentNumber:
        new_var_name = "IH_i"
        currentNumber = BitVec(new_var_name, 256)
        path_conditions_and_vars[new_var_name] = currentNumber

    if not currentDifficulty:
        new_var_name = "IH_d"
        currentDifficulty = BitVec(new_var_name, 256)
        path_conditions_and_vars[new_var_name] = currentDifficulty

    if not currentGasLimit:
        new_var_name = "IH_l"
        currentGasLimit = BitVec(new_var_name, 256)
        path_conditions_and_vars[new_var_name] = currentGasLimit

    if not currentChainId:
        new_var_name = "IH_cid"
        currentChainId = BitVec(new_var_name, 256)
        path_conditions_and_vars[new_var_name] = currentChainId

    if not currentBaseFee:
        new_var_name = "IH_f"
        currentBaseFee = BitVec(new_var_name, 256)
        path_conditions_and_vars[new_var_name] = currentBaseFee

    if not currentTimestamp:
        new_var_name = "IH_s"
        currentTimestamp = BitVec(new_var_name, 256)
        path_conditions_and_vars[new_var_name] = currentTimestamp

    path_conditions_and_vars["input"] = []
    path_conditions_and_vars["input"].append(deposited_value)

    # the state of the current contract
    if "Ia" not in global_state:
        global_state["Ia"] = {}
    global_state["miu_i"] = 0
    global_state["value"] = deposited_value
    global_state["sender_address"] = sender_address
    global_state["receiver_address"] = receiver_address
    global_state["gas_price"] = gas_price
    global_state["origin"] = origin
    global_state["currentCoinbase"] = currentCoinbase
    global_state["currentTimestamp"] = currentTimestamp
    global_state["currentNumber"] = currentNumber
    global_state["currentDifficulty"] = currentDifficulty
    global_state["currentGasLimit"] = currentGasLimit

    global_state["currentChainId"] = currentChainId
    global_state["currentSelfBalance"] = currentSelfBalance
    global_state["currentBaseFee"] = currentBaseFee

    # the state of gates to detect each defect
    global_state["var_to_operator"] = {}
    global_state["token_flow"] = []
    global_state["conditional_statement"] = {
        "trigger": False, 
        "statement_type": None, # if, require, assert
        "comparison_type": None, # GT, LT, EQ, GT_and_EQ, LT_and_EQ
        "first": None, 
        "second": None, 
    }
    global_state["func_jump_path"] = []
    global_state["ETH_flow"] = False


    return global_state


def get_start_block_to_func_sig():
    """Map block to function signature

    Returns:
        dict: pc tp function signature
    """
    state = 0
    func_sig = None
    for pc, instr in six.iteritems(instructions):
        if state == 0 and instr.startswith("PUSH4"):
            state += 1
            func_sig = instr.split(" ")[1][2:]
        elif state == 1 and instr.startswith("EQ"):
            state += 1
        elif state == 2 and instr.startswith("PUSH"):
            state = 0
            pc = instr.split(" ")[1]
            pc = int(pc, 16)
            start_block_to_func_sig[pc] = func_sig
        else:
            state = 0
    return start_block_to_func_sig


def full_sym_exec():
    # executing, starting from beginning
    path_conditions_and_vars = {"path_condition": []}
    global_state = get_init_global_state(path_conditions_and_vars)

    params = Parameter(
        path_conditions_and_vars=path_conditions_and_vars,
        global_state=global_state,
    )
    if g_src_map:
        start_block_to_func_sig = get_start_block_to_func_sig()

    ### 
    # with live:
    #     return sym_exec_block(params, 0, 0, 0, -1, "fallback")
    return sym_exec_block(params, 0, 0, 0, -1, "fallback")


# Symbolically executing a block from the start address
def sym_exec_block(params, block, pre_block, depth, func_call, current_func_name):
    global solver
    global visited_edges
    global global_problematic_pcs
    global all_gs
    global results
    global g_src_map

    global pruned_function

    visited = params.visited
    stack = params.stack
    mem = params.mem
    mem_real = params.mem_real
    global_state = params.global_state
    sha3_list = params.sha3_list
    path_conditions_and_vars = params.path_conditions_and_vars


    # Factory Function for tuples is used as dictionary key
    Edge = namedtuple("Edge", ["v1", "v2"])
    if block < 0:
        log.debug("UNKNOWN JUMP ADDRESS. TERMINATING THIS PATH")
        return ["ERROR"]

    log.debug("Reach block address %d \n", block)

    if g_src_map:
        if block in start_block_to_func_sig:
            func_sig = start_block_to_func_sig[block]
            current_func_name = g_src_map.sig_to_func[func_sig]
            pattern = r"(\w[\w\d_]*)\((.*)\)$"
            match = re.match(pattern, current_func_name)
            if match:
                current_func_name = list(match.groups())[0]

                if len(pruned_function) > 0:
                    if current_func_name not in pruned_function:
                        return

    current_edge = Edge(pre_block, block)
    if current_edge in visited_edges:
        updated_count_number = visited_edges[current_edge] + 1
        visited_edges.update({current_edge: updated_count_number})
    else:
        visited_edges.update({current_edge: 1})

    if visited_edges[current_edge] > global_params.LOOP_LIMIT:
        log.debug("Overcome a number of loop limit. Terminating this path ...")
        return stack

    # Execute every instruction, one at a time
    try:
        block_ins = vertices[block].get_instructions()
    except KeyError:
        log.debug("This path results in an exception, possibly an invalid jump address")
        return ["ERROR"]

    find_conditional_block(block_ins, global_state, g_src_map)

    for instr in block_ins:
        sym_exec_ins(params, block, instr, func_call, current_func_name)

    # Mark that this basic block in the visited blocks
    visited.append(block)
    depth += 1

    # Go to next Basic Block(s)
    if jump_type[block] == "terminal" or depth > global_params.DEPTH_LIMIT:
        global total_no_of_paths
        global no_of_test_cases

        total_no_of_paths += 1

        if global_params.GENERATE_TEST_CASES:
            try:
                model = solver.model()
                no_of_test_cases += 1
                filename = "test%s.otest" % no_of_test_cases
                with open(filename, "w") as f:
                    for variable in model.decls():
                        f.write(str(variable) + " = " + str(model[variable]) + "\n")
                if os.stat(filename).st_size == 0:
                    os.remove(filename)
                    no_of_test_cases -= 1
            except Exception as e:
                pass

        log.debug("TERMINATING A PATH ...")

        updated_count_number = visited_edges[current_edge] - 1
        visited_edges.update({current_edge: updated_count_number})
    elif jump_type[block] == "unconditional":  # executing "JUMP"
        successor = vertices[block].get_jump_target()
        new_params = params.copy()
        new_params.global_state["pc"] = successor
        if g_src_map:
            source_code = g_src_map.get_source_code(global_state["pc"])
            if source_code in g_src_map.func_call_names:
                if (source_code.startswith("_tokenTransfer(")):
                    return
                func_call = global_state["pc"]
                new_params.global_state["func_jump_path"].append(global_state["pc"])
        sym_exec_block(
            new_params, successor, block, depth, func_call, current_func_name
        )

        updated_count_number = visited_edges[current_edge] - 1
        visited_edges.update({current_edge: updated_count_number})
    elif jump_type[block] == "falls_to":  # just follow to the next basic block
        successor = vertices[block].get_falls_to()
        new_params = params.copy()
        new_params.global_state["pc"] = successor
        sym_exec_block(
            new_params, successor, block, depth, func_call, current_func_name
        )

        updated_count_number = visited_edges[current_edge] - 1
        visited_edges.update({current_edge: updated_count_number})
    elif jump_type[block] == "conditional":  # executing "JUMPI"
        # A choice point, we proceed with depth first search

        branch_expression = vertices[block].get_branch_expression()

        log.debug("Branch expression: " + str(branch_expression))

        check_div_in_path(branch_expression, global_state, global_problematic_pcs, g_src_map, path_conditions_and_vars)

        solver.push()  # SET A BOUNDARY FOR SOLVER
        solver.add(branch_expression)

        try:
            ret = solver.check()
            if ret == unknown:
                log.debug("z3 unknow happend:reason:" + solver.reason_unknown())
                log.debug("left branch:block:"+ str(block) + ":current_func_name:" + str(current_func_name))
                # raise Z3Exception(solver.reason_unknown())
            if ret == unsat:
                log.debug("INFEASIBLE PATH DETECTED")
            else:
                left_branch = vertices[block].get_jump_target()
                new_params = params.copy()
                new_params.global_state["pc"] = left_branch
                new_params.path_conditions_and_vars["path_condition"].append(
                    branch_expression
                )
                last_idx = (
                    len(new_params.path_conditions_and_vars["path_condition"]) - 1
                )
                sym_exec_block(
                    new_params, left_branch, block, depth, func_call, current_func_name
                )
        except TimeoutError:
            raise
        except Exception as e:
            if global_params.DEBUG_MODE:
                traceback.print_exc()

                exit(-1)

        solver.pop()  # POP SOLVER CONTEXT

        solver.push()  # SET A BOUNDARY FOR SOLVER
        negated_branch_expression = Not(branch_expression)
        solver.add(negated_branch_expression)

        log.debug("Negated branch expression: " + str(negated_branch_expression))

        try:
            ret = solver.check()
            if ret == unknown:
                log.debug("z3 unknow happend:reason:" + solver.reason_unknown())
                log.debug("right branch:block:"+ str(block) + ":current_func_name:" + str(current_func_name))
                # raise Z3Exception(solver.reason_unknown())
            if ret == unsat:
                log.debug("INFEASIBLE PATH DETECTED")
            
            else:
                right_branch = vertices[block].get_falls_to()
                new_params = params.copy()
                new_params.global_state["pc"] = right_branch
                new_params.path_conditions_and_vars["path_condition"].append(
                    negated_branch_expression
                )
                last_idx = (
                    len(new_params.path_conditions_and_vars["path_condition"]) - 1
                )
                sym_exec_block(
                    new_params, right_branch, block, depth, func_call, current_func_name
                )
        except TimeoutError:
            raise
        except Exception as e:
            if global_params.DEBUG_MODE:
                traceback.print_exc()

                exit(-1)

        solver.pop()  # POP SOLVER CONTEXT
        updated_count_number = visited_edges[current_edge] - 1
        visited_edges.update({current_edge: updated_count_number})
    else:
        updated_count_number = visited_edges[current_edge] - 1
        visited_edges.update({current_edge: updated_count_number})
        raise Exception("Unknown Jump-Type")


# Symbolically executing an instruction
def sym_exec_ins(params, block, instr, func_call, current_func_name):
    global MSIZE
    global visited_pcs
    global solver
    global vertices
    global edges
    global blocks
    global g_src_map
    global g_slot_map
    global instructions

    stack = params.stack
    mem = params.mem
    mem_real = params.mem_real
    global_state = params.global_state
    sha3_list = params.sha3_list
    path_conditions_and_vars = params.path_conditions_and_vars

    visited_pcs.add(global_state["pc"])

    instr_parts = str.split(instr, " ")
    opcode = instr_parts[0]

    if opcode == "INVALID":
        global_state["pc"] = global_state["pc"] + 1
        return
    elif opcode == "ASSERTFAIL":
        global_state["pc"] = global_state["pc"] + 1
        return

    # collecting the analysis result by calling this skeletal function
    # this should be done before symbolically executing the instruction,
    # since SE will modify the stack and mem
    # semantic_analysis(
    #     analysis,
    #     opcode,
    #     stack,
    #     mem,
    #     global_state,
    #     global_problematic_pcs,
    #     current_func_name,
    #     g_src_map,
    #     path_conditions_and_vars,
    #     solver,
    #     instructions,
    #     g_slot_map,
    # )

    precision_loss_analysis(
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
    )

    # block coverage
    total_blocks = len(vertices)
    visited_blocks.add(block)
    block_coverage = len(visited_blocks) / total_blocks * 100

    # instruction coverage
    perc = float(len(visited_pcs)) / len(instructions.keys()) * 100

    ### 
    # update per 5% change in code coverage
    # if int(perc) % 5 == 0:
    #     live.update(
    #         generate_table(
    #             opcode,
    #             block_coverage,
    #             global_state["pc"],
    #             perc,
    #             g_src_map,
    #             global_problematic_pcs,
    #             current_func_name,
    #         ),
    #         refresh=True,
    #     )

    log.debug("==============================")
    log.debug("EXECUTING: " + instr)

    #
    #  0s: Stop and Arithmetic Operations
    #
    if opcode == "STOP":
        global_state["pc"] = global_state["pc"] + 1
        return
    elif opcode == "ADD":
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            first = stack.pop(0)
            second = stack.pop(0)
            # Type conversion is needed when they are mismatched
            if isReal(first) and isSymbolic(second):
                first = BitVecVal(first, 256)
                computed = first + second
            elif isSymbolic(first) and isReal(second):
                second = BitVecVal(second, 256)
                computed = first + second
            else:
                # both are real and we need to manually modulus with 2 ** 256
                # if both are symbolic z3 takes care of modulus automatically
                computed = (first + second) % (2**256)
            computed = simplify(computed) if is_expr(computed) else computed

            if isSymbolic(computed) or isSymbolic(first) or isSymbolic(second):
                if str(first) != str(computed) and str(second) != str(computed):
                    global_state["var_to_operator"][computed] = [first, "add", second, global_state["pc"] - 1]

            stack.insert(0, computed)
        else:
            raise ValueError("STACK underflow")
    elif opcode == "MUL":
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            first = stack.pop(0)
            second = stack.pop(0)
            if isReal(first) and isSymbolic(second):
                first = BitVecVal(first, 256)
            elif isSymbolic(first) and isReal(second):
                second = BitVecVal(second, 256)
            computed = first * second & UNSIGNED_BOUND_NUMBER
            computed = simplify(computed) if is_expr(computed) else computed

            if isSymbolic(computed) or isSymbolic(first) or isSymbolic(second):
                if str(first) != str(computed) and str(second) != str(computed):
                    global_state["var_to_operator"][computed] = [first, 'mul', second, global_state["pc"] - 1]

            stack.insert(0, computed)
        else:
            raise ValueError("STACK underflow")
    elif opcode == "SUB":
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            first = stack.pop(0)
            second = stack.pop(0)
            if isReal(first) and isSymbolic(second):
                first = BitVecVal(first, 256)
                computed = first - second
            elif isSymbolic(first) and isReal(second):
                second = BitVecVal(second, 256)
                computed = first - second
            else:
                computed = (first - second) % (2**256)
            computed = simplify(computed) if is_expr(computed) else computed

            if isSymbolic(computed) or isSymbolic(first) or isSymbolic(second):
                if str(first) != str(computed) and str(second) != str(computed):
                    global_state["var_to_operator"][computed] = [first, "sub", second, global_state["pc"] - 1]

            stack.insert(0, computed)
        else:
            raise ValueError("STACK underflow")
    elif opcode == "DIV":
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            first = stack.pop(0)
            second = stack.pop(0)
            if isAllReal(first, second):
                if second == 0:
                    computed = 0
                else:
                    first = to_unsigned(first)
                    second = to_unsigned(second)
                    computed = first // second
            else:
                first = to_symbolic(first)
                second = to_symbolic(second)
                # The program will check itself, no need to check here
                computed = UDiv(first, second)
            computed = simplify(computed) if is_expr(computed) else computed

 
            if isSymbolic(computed) or isSymbolic(first) or isSymbolic(second):
                if str(first) != str(computed) and str(second) != str(computed):
                    # global_state["var_to_operator"][computed] = [first, 'div', second, global_state["pc"] - 1]
                    if isReal(second):
                        hex_second = hex(second)
                        if hex_second.startswith("0x1") and all(c == "0" for c in hex_second[3:]) and len(hex_second) >= 7:
                            pass
                        else:
                            global_state["var_to_operator"][computed] = [first, 'div', second, global_state["pc"] - 1]
                    else:
                        global_state["var_to_operator"][computed] = [first, 'div', second, global_state["pc"] - 1]

            stack.insert(0, computed)
        else:
            raise ValueError("STACK underflow")
    elif opcode == "SDIV":
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            first = stack.pop(0)
            second = stack.pop(0)
            if isAllReal(first, second):
                first = to_signed(first)
                second = to_signed(second)
                if second == 0:
                    computed = 0
                elif first == -(2**255) and second == -1:
                    computed = -(2**255)
                else:
                    sign = -1 if (first / second) < 0 else 1
                    computed = sign * (abs(first) / abs(second))
            else:
                first = to_symbolic(first)
                second = to_symbolic(second)

                computed = first / second
            computed = simplify(computed) if is_expr(computed) else computed
            stack.insert(0, computed)
        else:
            raise ValueError("STACK underflow")
    elif opcode == "MOD":
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            first = stack.pop(0)
            second = stack.pop(0)
            if isAllReal(first, second):
                if second == 0:
                    computed = 0
                else:
                    first = to_unsigned(first)
                    second = to_unsigned(second)
                    computed = first % second & UNSIGNED_BOUND_NUMBER

            else:
                first = to_symbolic(first)
                second = to_symbolic(second)

                computed = URem(first, second)

            computed = simplify(computed) if is_expr(computed) else computed
            stack.insert(0, computed)
        else:
            raise ValueError("STACK underflow")
    elif opcode == "SMOD":
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            first = stack.pop(0)
            second = stack.pop(0)
            if isAllReal(first, second):
                if second == 0:
                    computed = 0
                else:
                    first = to_signed(first)
                    second = to_signed(second)
                    sign = -1 if first < 0 else 1
                    computed = sign * (abs(first) % abs(second))
            else:
                first = to_symbolic(first)
                second = to_symbolic(second)

                solver.push()
                solver.add(Not(second == 0))
                if check_sat(solver) == unsat:
                    # it is provable that second is indeed equal to zero
                    computed = 0
                else:
                    solver.push()
                    solver.add(first < 0)  # check sign of first element
                    sign = (
                        BitVecVal(-1, 256)
                        if check_sat(solver) == sat
                        else BitVecVal(1, 256)
                    )
                    solver.pop()

                    def z3_abs(x):
                        return If(x >= 0, x, -x)

                    first = z3_abs(first)
                    second = z3_abs(second)

                    computed = sign * (first % second)
                solver.pop()

            computed = simplify(computed) if is_expr(computed) else computed
            stack.insert(0, computed)
        else:
            raise ValueError("STACK underflow")
    elif opcode == "ADDMOD":
        if len(stack) > 2:
            global_state["pc"] = global_state["pc"] + 1
            first = stack.pop(0)
            second = stack.pop(0)
            third = stack.pop(0)

            if isAllReal(first, second, third):
                if third == 0:
                    computed = 0
                else:
                    computed = (first + second) % third
            else:
                first = to_symbolic(first)
                second = to_symbolic(second)
                solver.push()
                solver.add(Not(third == 0))
                if check_sat(solver) == unsat:
                    computed = 0
                else:
                    first = ZeroExt(256, first)
                    second = ZeroExt(256, second)
                    third = ZeroExt(256, third)
                    computed = (first + second) % third
                    computed = Extract(255, 0, computed)
                solver.pop()
            computed = simplify(computed) if is_expr(computed) else computed
            stack.insert(0, computed)
        else:
            raise ValueError("STACK underflow")
    elif opcode == "MULMOD":
        if len(stack) > 2:
            global_state["pc"] = global_state["pc"] + 1
            first = stack.pop(0)
            second = stack.pop(0)
            third = stack.pop(0)

            if isAllReal(first, second, third):
                if third == 0:
                    computed = 0
                else:
                    computed = (first * second) % third
            else:
                first = to_symbolic(first)
                second = to_symbolic(second)
                solver.push()
                solver.add(Not(third == 0))
                if check_sat(solver) == unsat:
                    computed = 0
                else:
                    first = ZeroExt(256, first)
                    second = ZeroExt(256, second)
                    third = ZeroExt(256, third)
                    computed = URem(first * second, third)
                    computed = Extract(255, 0, computed)
                solver.pop()
            computed = simplify(computed) if is_expr(computed) else computed
            stack.insert(0, computed)
        else:
            raise ValueError("STACK underflow")
    elif opcode == "EXP":
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            base = stack.pop(0)
            exponent = stack.pop(0)
            # Type conversion is needed when they are mismatched
            if isAllReal(base, exponent):
                computed = pow(base, exponent, 2**256)
            else:
                # The computed value is unknown, this is because power is
                # not supported in bit-vector theory
                new_var_name = gen.gen_arbitrary_var()
                computed = BitVec(new_var_name, 256)
            computed = simplify(computed) if is_expr(computed) else computed

            if isSymbolic(computed) or isSymbolic(base) or isSymbolic(exponent):
                if str(base) != str(computed) and str(exponent) != str(computed):
                    global_state["var_to_operator"][computed] = [base, 'exp', exponent, global_state["pc"] - 1]

            stack.insert(0, computed)
        else:
            raise ValueError("STACK underflow")
    elif opcode == "SIGNEXTEND":
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            first = stack.pop(0)
            second = stack.pop(0)
            if isAllReal(first, second):
                if first >= 32 or first < 0:
                    computed = second
                else:
                    signbit_index_from_right = 8 * first + 7
                    if second & (1 << signbit_index_from_right):
                        computed = second | (2**256 - (1 << signbit_index_from_right))
                    else:
                        computed = second & ((1 << signbit_index_from_right) - 1)
            else:
                first = to_symbolic(first)
                second = to_symbolic(second)
                solver.push()
                solver.add(Not(Or(first >= 32, first < 0)))
                if check_sat(solver) == unsat:
                    computed = second
                else:
                    signbit_index_from_right = 8 * first + 7
                    solver.push()
                    solver.add(second & (1 << signbit_index_from_right) == 0)
                    if check_sat(solver) == unsat:
                        computed = second | (2**256 - (1 << signbit_index_from_right))
                    else:
                        computed = second & ((1 << signbit_index_from_right) - 1)
                    solver.pop()
                solver.pop()
            computed = simplify(computed) if is_expr(computed) else computed
            stack.insert(0, computed)
        else:
            raise ValueError("STACK underflow")
    #
    #  10s: Comparison and Bitwise Logic Operations
    #
    elif opcode == "LT":
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            first = stack.pop(0)
            second = stack.pop(0)

            if isAllReal(first, second):
                first = to_unsigned(first)
                second = to_unsigned(second)
                if first < second:
                    computed = 1
                else:
                    computed = 0
            else:
                computed = If(ULT(first, second), BitVecVal(1, 256), BitVecVal(0, 256))
            computed = simplify(computed) if is_expr(computed) else computed

            handle_comparison(global_state, first, second)
            stack.insert(0, computed)
        else:
            raise ValueError("STACK underflow")
    elif opcode == "GT":
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            first = stack.pop(0)
            second = stack.pop(0)

            if isAllReal(first, second):
                first = to_unsigned(first)
                second = to_unsigned(second)
                if first > second:
                    computed = 1
                else:
                    computed = 0
            else:
                computed = If(UGT(first, second), BitVecVal(1, 256), BitVecVal(0, 256))
            computed = simplify(computed) if is_expr(computed) else computed

            handle_comparison(global_state, first, second)
            stack.insert(0, computed)
        else:
            raise ValueError("STACK underflow")
    elif opcode == "SLT":  # Not fully faithful to signed comparison
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            first = stack.pop(0)
            second = stack.pop(0)
            if isAllReal(first, second):
                first = to_signed(first)
                second = to_signed(second)
                if first < second:
                    computed = 1
                else:
                    computed = 0
            else:
                computed = If(first < second, BitVecVal(1, 256), BitVecVal(0, 256))
            computed = simplify(computed) if is_expr(computed) else computed
            stack.insert(0, computed)
        else:
            raise ValueError("STACK underflow")
    elif opcode == "SGT":  # Not fully faithful to signed comparison
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            first = stack.pop(0)
            second = stack.pop(0)
            if isAllReal(first, second):
                first = to_signed(first)
                second = to_signed(second)
                if first > second:
                    computed = 1
                else:
                    computed = 0
            else:
                computed = If(first > second, BitVecVal(1, 256), BitVecVal(0, 256))
            computed = simplify(computed) if is_expr(computed) else computed
            stack.insert(0, computed)
        else:
            raise ValueError("STACK underflow")
    elif opcode == "EQ":
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            first = stack.pop(0)
            second = stack.pop(0)
            if isAllReal(first, second):
                if first == second:
                    computed = 1
                else:
                    computed = 0
            else:
                computed = If(first == second, BitVecVal(1, 256), BitVecVal(0, 256))
            computed = simplify(computed) if is_expr(computed) else computed
            stack.insert(0, computed)
        else:
            raise ValueError("STACK underflow")
    elif opcode == "ISZERO":
        # Tricky: this instruction works on both boolean and integer,
        # when we have a symbolic expression, type error might occur
        # Currently handled by try and catch
        if len(stack) > 0:
            global_state["pc"] = global_state["pc"] + 1
            first = stack.pop(0)
            if isReal(first):
                if first == 0:
                    computed = 1
                else:
                    computed = 0
            else:
                computed = If(first == 0, BitVecVal(1, 256), BitVecVal(0, 256))
            computed = simplify(computed) if is_expr(computed) else computed
            stack.insert(0, computed)
        else:
            raise ValueError("STACK underflow")
    elif opcode == "AND":
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            first = stack.pop(0)
            second = stack.pop(0)
            computed = first & second
            computed = simplify(computed) if is_expr(computed) else computed
            stack.insert(0, computed)
        else:
            raise ValueError("STACK underflow")
    elif opcode == "OR":
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            first = stack.pop(0)
            second = stack.pop(0)

            computed = first | second
            computed = simplify(computed) if is_expr(computed) else computed
            stack.insert(0, computed)

        else:
            raise ValueError("STACK underflow")
    elif opcode == "XOR":
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            first = stack.pop(0)
            second = stack.pop(0)

            computed = first ^ second
            computed = simplify(computed) if is_expr(computed) else computed
            stack.insert(0, computed)

        else:
            raise ValueError("STACK underflow")
    elif opcode == "NOT":
        if len(stack) > 0:
            global_state["pc"] = global_state["pc"] + 1
            first = stack.pop(0)
            computed = (~first) & UNSIGNED_BOUND_NUMBER
            computed = simplify(computed) if is_expr(computed) else computed
            stack.insert(0, computed)
        else:
            raise ValueError("STACK underflow")
    elif opcode == "BYTE":
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            first = stack.pop(0)
            byte_index = 32 - first - 1
            second = stack.pop(0)

            if isAllReal(first, second):
                if first >= 32 or first < 0:
                    computed = 0
                else:
                    computed = second & (255 << (8 * byte_index))
                    computed = computed >> (8 * byte_index)
            else:
                first = to_symbolic(first)
                second = to_symbolic(second)
                solver.push()
                solver.add(Not(Or(first >= 32, first < 0)))
                if check_sat(solver) == unsat:
                    computed = 0
                else:
                    computed = second & (255 << (8 * byte_index))
                    computed = computed >> (8 * byte_index)
                solver.pop()
            computed = simplify(computed) if is_expr(computed) else computed
            stack.insert(0, computed)
        else:
            raise ValueError("STACK underflow")
    #
    # 20s: SHA3/KECCAK256
    #
    elif opcode in ["KECCAK256", "SHA3"]:
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1

            offset = stack.pop(0)
            size = stack.pop(0)
            if isAllReal(offset, size):
                valueList = load_size_mem_info(mem_real, offset, offset + size - 1)
                if len(valueList) > 0:
                    sorted_valueList = sorted(valueList, key=lambda x: (x["start"]))
                    sorted_values = [item["value"] for item in sorted_valueList]
                    data = [str(x) for x in sorted_values]
                    position = "".join(data)
                    position = hashlib.md5(position.encode()).hexdigest()

                    if position in sha3_list:
                        stack.insert(0, sha3_list[position])
                    else:
                        sha3_var_name = gen.gen_sha3_var()
                        sha3_var = BitVec(sha3_var_name, 256)
                        sha3_list[position] = sha3_var
                        stack.insert(0, sha3_var)
                else:
                    new_sha3_var_name = gen.gen_sha3_var()
                    new_sha3_var = BitVec(new_sha3_var_name, 256)
                    path_conditions_and_vars[new_sha3_var_name] = new_sha3_var
                    stack.insert(0, new_sha3_var)
            else:
                new_sha3_var_name = gen.gen_sha3_var()
                new_sha3_var = BitVec(new_sha3_var_name, 256)
                path_conditions_and_vars[new_sha3_var_name] = new_sha3_var
                stack.insert(0, new_sha3_var)
        else:
            raise ValueError("STACK underflow")
    #
    # 30s: Environment Information
    #
    elif opcode == "ADDRESS":  # get address of currently executing account
        global_state["pc"] = global_state["pc"] + 1
        stack.insert(0, global_state["receiver_address"])
    elif opcode == "BALANCE":
        if len(stack) > 0:
            global_state["pc"] = global_state["pc"] + 1
            address = stack.pop(0)
            if isReal(address):
                hashed_address = "concrete_address_" + str(address)
            else:
                hashed_address = str(address)

            if hashed_address in global_state["balance"]:
                balance = global_state["balance"][hashed_address]
            else:
                new_var_name = gen.gen_balance_var(hashed_address)
                if new_var_name in path_conditions_and_vars:
                    new_var = path_conditions_and_vars[new_var_name]
                else:
                    new_var = BitVec(new_var_name, 256)
                    path_conditions_and_vars[new_var_name] = new_var
                global_state["balance"][hashed_address] = new_var
                balance = new_var

            stack.insert(0, balance)
        else:
            raise ValueError("STACK underflow")
    elif opcode == "CALLER":  # get caller address
        # that is directly responsible for this execution
        global_state["pc"] = global_state["pc"] + 1
        stack.insert(0, global_state["sender_address"])
    elif opcode == "ORIGIN":  # get execution origination address
        global_state["pc"] = global_state["pc"] + 1
        stack.insert(0, global_state["origin"])
    elif opcode == "CALLVALUE":  # get value of this transaction
        global_state["pc"] = global_state["pc"] + 1
        stack.insert(0, global_state["value"])
        # buy function feature: msg.value to transfer the token

        if global_state["ETH_flow"] == False:
            add_token_flow("ETH", global_state["sender_address"], global_state["receiver_address"], global_state["value"], global_state, path_conditions_and_vars, global_problematic_pcs)
            global_state["ETH_flow"] = True

    elif opcode == "CALLDATALOAD":  # from inputter data from environment
        if len(stack) > 0:
            global_state["pc"] = global_state["pc"] + 1
            position = stack.pop(0)
            new_var_name = gen.gen_calldataload_var(position)
            if new_var_name in path_conditions_and_vars:
                new_var = path_conditions_and_vars[new_var_name]
            else:
                new_var = BitVec(new_var_name, 256)
                path_conditions_and_vars[new_var_name] = new_var
            stack.insert(0, new_var)

            if new_var not in path_conditions_and_vars["input"]:
                path_conditions_and_vars["input"].append(new_var)

        else:
            raise ValueError("STACK underflow")
    elif opcode == "CALLDATASIZE":
        global_state["pc"] = global_state["pc"] + 1
        calldata_size_var_name = gen.gen_calldata_size()
        if calldata_size_var_name in path_conditions_and_vars:
            calldata_size_var = path_conditions_and_vars[calldata_size_var_name]
        else:
            calldata_size_var = BitVec(calldata_size_var_name, 256)
            path_conditions_and_vars[calldata_size_var_name] = calldata_size_var
        stack.insert(0, calldata_size_var)
    elif opcode == "CALLDATACOPY":  # Copy inputter data to memory
        #  TODO: Don't know how to simulate this yet
        if len(stack) > 2:
            global_state["pc"] = global_state["pc"] + 1
            stack.pop(0)
            stack.pop(0)
            stack.pop(0)
        else:
            raise ValueError("STACK underflow")
    elif opcode == "CODESIZE":
        global_state["pc"] = global_state["pc"] + 1
        if g_disasm_file.endswith(".disasm"):
            evm_file_name = g_disasm_file[:-7]
        else:
            evm_file_name = g_disasm_file
        with open(evm_file_name, "r") as evm_file:
            # evm = evm_file.read()[:-1]
            evm = evm_file.read().strip()
            code_size = len(evm) / 2
            stack.insert(0, code_size)
    elif opcode == "CODECOPY":
        if len(stack) > 2:
            global_state["pc"] = global_state["pc"] + 1
            mem_location = stack.pop(0)
            code_from = stack.pop(0)
            no_bytes = stack.pop(0)

            if isAllReal(code_from, no_bytes):
                if g_disasm_file.endswith(".disasm"):
                    evm_file_name = g_disasm_file[:-7]
                else:
                    evm_file_name = g_disasm_file
                with open(evm_file_name, "r") as evm_file:
                    # evm = evm_file.read()[:-1]
                    evm = evm_file.read().strip()
                    start = code_from * 2
                    end = start + no_bytes * 2
                    code = evm[start:end]
                    code_var = int(code, 16)
            else:
                code_var_name = gen.gen_code_var("Ia", code_from, no_bytes)
                if code_var_name in path_conditions_and_vars:
                    code_var = path_conditions_and_vars[code_var_name]
                else:
                    code_var = BitVec(code_var_name, 256)
                    path_conditions_and_vars[code_var_name] = code_var

            
            if isAllReal(mem_location, no_bytes):
                meminfo = {
                    "start": mem_location,
                    "end": mem_location + no_bytes - 1,
                    "value": code_var
                }
                add_mem_info(meminfo, mem_real)
            else:
                mem[str(mem_location)] = code_var
        else:
            raise ValueError("STACK underflow")
    elif opcode == "RETURNDATACOPY":
        if len(stack) > 2:
            global_state["pc"] += 1
            stack.pop(0)
            stack.pop(0)
            stack.pop(0)
        else:
            raise ValueError("STACK underflow")
    elif opcode == "RETURNDATASIZE":
        global_state["pc"] += 1
        new_var_name = gen.gen_returndatasize_var()
        # new_var_name = gen.gen_arbitrary_var()
        new_var = BitVec(new_var_name, 256)
        stack.insert(0, new_var)
    elif opcode == "GASPRICE":
        global_state["pc"] = global_state["pc"] + 1
        stack.insert(0, global_state["gas_price"])
    elif opcode == "EXTCODESIZE":
        if len(stack) > 0:
            global_state["pc"] = global_state["pc"] + 1
            address = stack.pop(0)

            # not handled yet
            new_var_name = gen.gen_code_size_var(address)
            if new_var_name in path_conditions_and_vars:
                new_var = path_conditions_and_vars[new_var_name]
            else:
                new_var = BitVec(new_var_name, 256)
                path_conditions_and_vars[new_var_name] = new_var
            stack.insert(0, new_var)
        else:
            raise ValueError("STACK underflow")
    elif opcode == "EXTCODECOPY":
        if len(stack) > 3:
            global_state["pc"] = global_state["pc"] + 1
            address = stack.pop(0)
            mem_location = stack.pop(0)
            code_from = stack.pop(0)
            no_bytes = stack.pop(0)

            code_var_name = gen.gen_code_var(address, code_from, no_bytes)
            if code_var_name in path_conditions_and_vars:
                code_var = path_conditions_and_vars[code_var_name]
            else:
                code_var = BitVec(code_var_name, 256)
                path_conditions_and_vars[code_var_name] = code_var

            if isAllReal(mem_location, no_bytes):
                meminfo = {
                    "start": mem_location,
                    "end": mem_location + no_bytes - 1,
                    "value": code_var
                }
                add_mem_info(meminfo, mem_real)
            else:
                mem[str(mem_location)] = code_var

        else:
            raise ValueError("STACK underflow")

    elif opcode == "EXTCODEHASH":
        if len(stack) > 1:
            address = stack.pop(0)

            if(str(address) in sha3_list):
                stack.insert(0, sha3_list[str(address)])
            else:
                sha3_var_name = gen.gen_sha3_var()
                sha3_var = BitVec(sha3_var_name, 256)
                sha3_list[str(address)] = sha3_var
                stack.insert(0, sha3_var)
        else:
            raise ValueError('STACK underflow')

    #
    #  40s: Block Information
    #
    elif opcode == "BLOCKHASH":  # information from block header
        if len(stack) > 0:
            global_state["pc"] = global_state["pc"] + 1
            blocknumber = stack.pop(0)
            new_var_name = gen.gen_blockhash_var(blocknumber)
            if new_var_name in path_conditions_and_vars:
                new_var = path_conditions_and_vars[new_var_name]
            else:
                new_var = BitVec(new_var_name, 256)
                path_conditions_and_vars[new_var_name] = new_var
            stack.insert(0, new_var)
        else:
            raise ValueError("STACK underflow")
    elif opcode == "COINBASE":  # information from block header
        global_state["pc"] = global_state["pc"] + 1
        stack.insert(0, global_state["currentCoinbase"])
    elif opcode == "TIMESTAMP":  # information from block header
        global_state["pc"] = global_state["pc"] + 1
        stack.insert(0, global_state["currentTimestamp"])
    elif opcode == "NUMBER":  # information from block header
        global_state["pc"] = global_state["pc"] + 1
        stack.insert(0, global_state["currentNumber"])
    elif opcode == "DIFFICULTY":  # information from block header
        global_state["pc"] = global_state["pc"] + 1
        stack.insert(0, global_state["currentDifficulty"])
    elif opcode == "GASLIMIT":  # information from block header
        global_state["pc"] = global_state["pc"] + 1
        stack.insert(0, global_state["currentGasLimit"])
    #
    #  50s: Stack, Memory, Storage, and Flow Information
    #
    elif opcode == "POP":
        if len(stack) > 0:
            global_state["pc"] = global_state["pc"] + 1
            stack.pop(0)
        else:
            raise ValueError("STACK underflow")
    elif opcode == "MLOAD":
        if len(stack) > 0:
            global_state["pc"] = global_state["pc"] + 1
            stored_address = stack.pop(0)
            if isReal(stored_address):
                flag, info = load_mem_info(mem_real, stored_address, stored_address + 31)
                if not flag:
                    var_name =  gen.gen_mem_var(stored_address)
                    new_var = BitVec(var_name, 256)
                    stack.insert(0, new_var)

                    meminfo = {
                        "start": stored_address,
                        "end": stored_address + 31,
                        "value": new_var
                    }
                    add_mem_info(meminfo, mem_real)

                else:
                    stack.insert(0, info["value"])
            else:
                if str(stored_address) not in mem:
                    var_name =  gen.gen_mem_var(stored_address)
                    new_var = BitVec(var_name, 256)
                    mem[str(stored_address)] = new_var
                stack.insert(0, mem[str(stored_address)])
            
        else:
            raise ValueError("STACK underflow")
    elif opcode == "MSTORE":
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            stored_address = stack.pop(0)
            stored_value = stack.pop(0)
            # MSTORE slotid to MEM32

            if isReal(stored_address):
                # mem[stored_address] = stored_value
                meminfo = {
                    "start": stored_address, 
                    "end": stored_address + 31, 
                    "value": stored_value
                }
                add_mem_info(meminfo, mem_real)
            else:
                mem[str(stored_address)] = stored_value
        else:
            raise ValueError("STACK underflow")
    elif opcode == "MSTORE8":
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            stored_address = stack.pop(0)
            temp_value = stack.pop(0)
            stored_value = temp_value % 256  # get the least byte

            if isReal(stored_address):
                # mem[stored_address] = stored_value
                meminfo = {
                    "start": stored_address,
                    "end": stored_address,
                    "value": stored_value
                }
                add_mem_info(meminfo, mem_real)
            else:
                mem[str(stored_address)] = stored_value
        else:
            raise ValueError("STACK underflow")
    elif opcode == "SLOAD":
        if len(stack) > 0:
            global_state["pc"] = global_state["pc"] + 1
            position = stack.pop(0)

            if isReal(position) and position in global_state["Ia"]:
                value = global_state["Ia"][position]
                stack.insert(0, value)
            else:
                if str(position) in global_state["Ia"]:
                    value = global_state["Ia"][str(position)]
                    stack.insert(0, value)
                else:
                    if is_expr(position):
                        position = simplify(position)

                    new_var_name = gen.gen_store_var(position)
                    # ?Prev Edition to get param name

                    if new_var_name in path_conditions_and_vars:
                        new_var = path_conditions_and_vars[new_var_name]
                    else:
                        new_var = BitVec(new_var_name, 256)
                        path_conditions_and_vars[new_var_name] = new_var
                    stack.insert(0, new_var)
                    if isReal(position):
                        global_state["Ia"][position] = new_var
                    else:
                        global_state["Ia"][str(position)] = new_var
        else:
            raise ValueError("STACK underflow")

    elif opcode == "SSTORE":
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            stored_address = stack.pop(0)
            stored_value = stack.pop(0)

            if isReal(stored_address):
                # note that the stored_value could be unknown
                global_state["Ia"][stored_address] = stored_value
            else:
                # note that the stored_value could be unknown
                global_state["Ia"][str(stored_address)] = stored_value
        else:
            raise ValueError("STACK underflow")
    elif opcode == "JUMP":
        if len(stack) > 0:
            target_address = stack.pop(0)
            if isSymbolic(target_address):
                try:
                    target_address = int(str(simplify(target_address)))
                except:
                    raise TypeError("Target address must be an integer")
            vertices[block].set_jump_target(target_address)
            if target_address not in edges[block]:
                edges[block].append(target_address)
        else:
            raise ValueError("STACK underflow")
    elif opcode == "JUMPI":
        # We need to prepare two branches
        if len(stack) > 1:
            target_address = stack.pop(0)

            if isSymbolic(target_address):
                try:
                    target_address = int(str(simplify(target_address)))
                except:
                    raise TypeError("Target address must be an integer")
            vertices[block].set_jump_target(target_address)
            flag = stack.pop(0)
            branch_expression = BitVecVal(0, 1) == BitVecVal(1, 1)
            if isReal(flag):
                if flag != 0:
                    branch_expression = True
            else:
                branch_expression = flag != 0
            vertices[block].set_branch_expression(branch_expression)
            if target_address not in edges[block]:
                edges[block].append(target_address)
        else:
            raise ValueError("STACK underflow")
    elif opcode == "PC":
        stack.insert(0, global_state["pc"])
        global_state["pc"] = global_state["pc"] + 1
    elif opcode == "MSIZE":
        global_state["pc"] = global_state["pc"] + 1
        # msize = 32 * global_state["miu_i"]
        new_msize_var_name = gen.gen_msize_var()
        new_msize_var = BitVec(new_msize_var_name, 256)
        path_conditions_and_vars[new_msize_var_name] = new_msize_var
        stack.insert(0, new_msize_var)
    elif opcode == "GAS":
        # In general, we do not have this precisely. It depends on both
        # the initial gas and the amount has been depleted
        # we need o think about this in the future, in case precise gas
        # can be tracked
        global_state["pc"] = global_state["pc"] + 1
        new_var_name = gen.gen_gas_var()
        new_var = BitVec(new_var_name, 256)
        path_conditions_and_vars[new_var_name] = new_var
        stack.insert(0, new_var)
    elif opcode == "JUMPDEST":
        # Literally do nothing
        global_state["pc"] = global_state["pc"] + 1
    #
    #  60s & 70s: Push Operations
    #
    elif opcode.startswith("PUSH", 0):  # this is a push instruction
        position = int(opcode[4:], 10)
        global_state["pc"] = global_state["pc"] + 1 + position
        pushed_value = int(instr_parts[1], 16)
        stack.insert(0, pushed_value)
        if global_params.UNIT_TEST == 3:  # test evm symbolic
            stack[0] = BitVecVal(stack[0], 256)
    #
    #  80s: Duplication Operations
    #
    elif opcode.startswith("DUP", 0):
        global_state["pc"] = global_state["pc"] + 1
        position = int(opcode[3:], 10) - 1
        if len(stack) > position:
            duplicate = stack[position]
            stack.insert(0, duplicate)
        else:
            raise ValueError("STACK underflow")

    #
    #  90s: Swap Operations
    #
    elif opcode.startswith("SWAP", 0):
        global_state["pc"] = global_state["pc"] + 1
        position = int(opcode[4:], 10)
        if len(stack) > position:
            temp = stack[position]
            stack[position] = stack[0]
            stack[0] = temp
        else:
            raise ValueError("STACK underflow")

    #
    #  a0s: Logging Operations
    #
    elif opcode in ("LOG0", "LOG1", "LOG2", "LOG3", "LOG4"):
        global_state["pc"] = global_state["pc"] + 1
        # We do not simulate these log operations
        num_of_pops = 2 + int(opcode[3:])
        if len(stack) >= num_of_pops:
            while num_of_pops > 0:
                stack.pop(0)
                num_of_pops -= 1
        else:
            raise ValueError("STACK underflow")
    #
    #  f0s: System Operations
    #
    elif opcode in ["CREATE", "CREATE2"]:
        if len(stack) > 2:
            global_state["pc"] += 1
            stack.pop(0)
            stack.pop(0)
            stack.pop(0)
            new_var_name = gen.gen_arbitrary_var()
            new_var = BitVec(new_var_name, 256)
            stack.insert(0, new_var)
        else:
            raise ValueError("STACK underflow")
    elif opcode == "CALL":
        # TODO: Need to handle miu_i
        if len(stack) > 6:
            global_state["pc"] = global_state["pc"] + 1
            outgas = stack.pop(0)
            recipient = stack.pop(0)
            transfer_amount = stack.pop(0)
            start_data_input = stack.pop(0)
            size_data_input = stack.pop(0)
            start_data_output = stack.pop(0)
            size_data_ouput = stack.pop(0)

            # in the paper, it is shaky when the size of data output is
            # min of stack[6] and the | o |

            return_data_var_name = gen.gen_return_data()
            if return_data_var_name in path_conditions_and_vars:
                return_data_var = path_conditions_and_vars[return_data_var_name]
            else:
                return_data_var = BitVec(return_data_var_name, 256)
                path_conditions_and_vars[return_data_var_name] = return_data_var
            
            if isReal(transfer_amount):
                if transfer_amount == 0:
                    stack.insert(0, 1)  # x = 0

                    if isReal(size_data_ouput):
                        if size_data_ouput == 0:
                            pass
                        else:
                            if isReal(start_data_output):
                                meminfo = {
                                    "start": start_data_output,
                                    "end": start_data_output + size_data_ouput - 1,
                                    "value": return_data_var
                                }
                                add_mem_info(meminfo, mem_real)
                                
                            elif isSymbolic(start_data_output):
                                for i in range(size_data_ouput):
                                    index = simplify(start_data_output + i)
                                    if str(index) in mem:
                                        mem.pop(str(index))
                                mem[str(start_data_output)] = return_data_var
                    
                    return

            # Let us ignore the call depth
            balance_ia = global_state["balance"]["Ia"]
            is_enough_fund = transfer_amount <= balance_ia
            solver.push()
            solver.add(is_enough_fund)

            if check_sat_with_no_raise_exception(solver) == unsat:
                # this means not enough fund, thus the execution will result in exception
                solver.pop()
                stack.insert(0, 0)  # x = 0
            else:
                # the execution is possibly okay
                stack.insert(0, 1)  # x = 1
                solver.pop()

                if isReal(size_data_ouput):
                    if size_data_ouput == 0:
                        pass
                    else:
                        if isReal(start_data_output):
                            meminfo = {
                                "start": start_data_output,
                                "end": start_data_output + size_data_ouput - 1,
                                "value": return_data_var
                            }
                            add_mem_info(meminfo, mem_real)
                            
                        elif isSymbolic(start_data_output):
                            for i in range(size_data_ouput):
                                index = simplify(start_data_output + i)
                                if str(index) in mem:
                                    mem.pop(str(index))
                            mem[str(start_data_output)] = return_data_var

                solver.add(is_enough_fund)
                path_conditions_and_vars["path_condition"].append(is_enough_fund)
                last_idx = len(path_conditions_and_vars["path_condition"]) - 1
                new_balance_ia = balance_ia - transfer_amount
                global_state["balance"]["Ia"] = new_balance_ia
                address_is = path_conditions_and_vars["Is"]

                address_is = simplify(address_is & CONSTANT_ONES_159)
                if (address_is == recipient):
                    new_balance_is = global_state["balance"]["Is"] + transfer_amount
                    global_state["balance"]["Is"] = new_balance_is
                else:
                    if isReal(recipient):
                        new_address_name = "concrete_address_" + str(recipient)
                    else:
                        new_address_name = str(recipient)

                    if new_address_name in global_state["balance"]:
                        old_balance = global_state["balance"][new_address_name]
                    else:
                        old_balance_name = gen.gen_balance_var(new_address_name)
                        
                        if old_balance_name in path_conditions_and_vars:
                            old_balance = path_conditions_and_vars[old_balance_name]
                        else:
                            old_balance = BitVec(old_balance_name, 256)
                            path_conditions_and_vars[old_balance_name] = old_balance

                    constraint = old_balance >= 0
                    solver.add(constraint)
                    path_conditions_and_vars["path_condition"].append(constraint)
                    new_balance = old_balance + transfer_amount
                    global_state["balance"][new_address_name] = new_balance
        else:
            raise ValueError("STACK underflow")
    elif opcode == "CALLCODE":
        # TODO: Need to handle miu_i
        if len(stack) > 6:
            global_state["pc"] = global_state["pc"] + 1
            outgas = stack.pop(0)
            recipient = stack.pop(0)  # this is not used as recipient

            transfer_amount = stack.pop(0)
            start_data_input = stack.pop(0)
            size_data_input = stack.pop(0)
            start_data_output = stack.pop(0)
            size_data_ouput = stack.pop(0)
            # in the paper, it is shaky when the size of data output is
            # min of stack[6] and the | o |

            if isReal(transfer_amount):
                if transfer_amount == 0:
                    stack.insert(0, 1)  # x = 0
                    return

            # Let us ignore the call depth
            balance_ia = global_state["balance"]["Ia"]
            is_enough_fund = transfer_amount <= balance_ia
            solver.push()
            solver.add(is_enough_fund)

            if check_sat_with_no_raise_exception(solver) == unsat:
                # this means not enough fund, thus the execution will result in exception
                solver.pop()
                stack.insert(0, 0)  # x = 0
            else:
                # the execution is possibly okay
                stack.insert(0, 1)  # x = 1
                solver.pop()
                solver.add(is_enough_fund)
                path_conditions_and_vars["path_condition"].append(is_enough_fund)
                last_idx = len(path_conditions_and_vars["path_condition"]) - 1
        else:
            raise ValueError("STACK underflow")
    elif opcode in ("DELEGATECALL", "STATICCALL"):
        if len(stack) > 5:
            global_state["pc"] += 1
            stack.pop(0)
            recipient = stack.pop(0)

            stack.pop(0)
            stack.pop(0)
            stack.pop(0)
            stack.pop(0)
            new_var_name = gen.gen_DSCALL_res_var()
            new_var = BitVec(new_var_name, 256)
            stack.insert(0, new_var)
        else:
            raise ValueError("STACK underflow")
    elif opcode in ("RETURN", "REVERT"):
        # TODO: Need to handle miu_i
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            stack.pop(0)
            stack.pop(0)
            # TODO
            pass
        else:
            raise ValueError("STACK underflow")
    elif opcode == "SELFDESTRUCT":
        global_state["pc"] = global_state["pc"] + 1
        recipient = stack.pop(0)
        transfer_amount = global_state["balance"]["Ia"]
        global_state["balance"]["Ia"] = 0

        if isReal(recipient):
            hashed_address = "concrete_address_" + str(recipient)
        else:
            hashed_address = str(recipient)

        if hashed_address in global_state["balance"]:
            old_balance = global_state["balance"][hashed_address]
        else:
            old_balance_name = gen.gen_balance_var(hashed_address)
            
            if old_balance_name in path_conditions_and_vars:
                old_balance = path_conditions_and_vars[old_balance_name]
            else:
                old_balance = BitVec(old_balance_name, 256)
                path_conditions_and_vars[old_balance_name] = old_balance

        constraint = old_balance >= 0
        # solver.add(constraint)
        path_conditions_and_vars["path_condition"].append(constraint)
        new_balance = old_balance + transfer_amount
        global_state["balance"][hashed_address] = new_balance
        # TODO
        return

    # brand new opcodes
    elif opcode == "SHL":
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            shift = stack.pop(0)
            value = stack.pop(0)
            if isReal(value):
                value = BitVecVal(value, 256)
            computed = value << shift

            computed = simplify(computed) if is_expr(computed) else computed
            stack.insert(0, computed)
        else:
            raise ValueError("STACK underflow")

    elif opcode == "SHR":
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            # *Simpler model
            shift = stack.pop(0)
            value = stack.pop(0)
            # Type conversion is needed when they are mismatched
            if isReal(value):
                value = BitVecVal(value, 256)
            computed = LShR(value, shift)

            computed = simplify(computed) if is_expr(computed) else computed
            stack.insert(0, computed)
        else:
            raise ValueError("STACK underflow")

    elif opcode == "SAR":
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            # *Simpler model
            shift = stack.pop(0)
            value = stack.pop(0)
            # Type conversion is needed when they are mismatched
            if isReal(value):
                value = BitVecVal(value, 256)
            computed = value >> shift

            computed = simplify(computed) if is_expr(computed) else computed
            stack.insert(0, computed)
        else:
            raise ValueError("STACK underflow")

    elif opcode == "SELFBALANCE":
        # address(this).balance
        global_state["pc"] = global_state["pc"] + 1
        stack.insert(0, global_state["balance"]["Ia"])

    elif opcode == "CHAINID":
        # chain_id = {  1 // mainnet
        #    {  2 // Morden testnet (disused)
        #    {  2 // Expanse mainnet
        #    {  3 // Ropsten testnet
        #    {  4 // Rinkeby testnet
        #    {  5 // Goerli testnet
        #    { 42 // Kovan testnet
        #    { ...
        global_state["pc"] = global_state["pc"] + 1
        stack.insert(0, global_state["currentChainId"])

    elif opcode == "BASEFEE":
        global_state["pc"] = global_state["pc"] + 1
        stack.insert(0, global_state["currentBaseFee"])

    else:
        log.info("UNKNOWN INSTRUCTION: " + opcode)
        if global_params.UNIT_TEST == 2 or global_params.UNIT_TEST == 3:
            log.critical("Unknown instruction: %s" % opcode)
            exit(UNKNOWN_INSTRUCTION)
        raise Exception("UNKNOWN INSTRUCTION: " + opcode)


class TimeoutError(Exception):
    pass


class Timeout:
    """Timeout class using ALARM signal."""

    def __init__(self, sec=10, error_message=os.strerror(errno.ETIME)):
        self.sec = sec
        self.error_message = error_message

    def __enter__(self):
        signal.signal(signal.SIGALRM, self._handle_timeout)
        signal.alarm(self.sec)

    def __exit__(self, *args):
        signal.alarm(0)  # disable alarm

    def _handle_timeout(self, signum, frame):
        raise TimeoutError(self.error_message)


def do_nothing():
    pass


def load_size_mem_info(mem_real, start, end):
    res = []
    for info in mem_real:
        if info["start"] >= start and info["end"] <= end:
            res.append(info)

    return res

def load_mem_info(mem_real, start, end):
    for info in mem_real:
        if start == info["start"] and end == info["end"]:
            return True,info
    return False,{}

def add_mem_info(meminfo, mem_real):    
    new_mem_real = []
    for info in mem_real:
        if info["end"] < meminfo["start"] or info["start"] > meminfo["end"]:
            new_mem_real.append(info)
    new_mem_real.append(meminfo)
    mem_real.clear()
    # mem_real = new_mem_real
    for info in new_mem_real:
        mem_real.append(info)
    # return new_mem_real

def run_build_cfg_and_analyze(timeout_cb=do_nothing):
    initGlobalVars()
    global g_timeout

    try:
        with Timeout(sec=global_params.GLOBAL_TIMEOUT):
            build_cfg_and_analyze()
        log.debug("Done Symbolic execution")
    except TimeoutError:
        g_timeout = True
        timeout_cb()


def test():
    global_params.GLOBAL_TIMEOUT = global_params.GLOBAL_TIMEOUT_TEST

    def timeout_cb():
        traceback.print_exc()
        exit(EXCEPTION)

    run_build_cfg_and_analyze(timeout_cb=timeout_cb)


def analyze():
    def timeout_cb():
        if global_params.DEBUG_MODE:
            traceback.print_exc()

    run_build_cfg_and_analyze(timeout_cb=timeout_cb)


def run(disasm_file=None, source_file=None, source_map=None, slot_map=None):
    """Run specific contracts with the given sources and extracted slot map"""
    global g_disasm_file
    global g_source_file
    global g_src_map
    global results
    global begin
    global g_slot_map

    g_disasm_file = disasm_file
    g_source_file = source_file
    g_src_map = source_map
    g_slot_map = slot_map

    if is_testing_evm():
        test()
    else:
        begin = time.time()
        log.info("\t============ Results of %s===========" % source_map.cname)
        analyze()
        
        
        ret = Identifier.detect_defects(
            instructions,
            results,
            g_src_map,
            visited_pcs,
            global_problematic_pcs,
            begin,
            g_disasm_file,
        )

        return ret
