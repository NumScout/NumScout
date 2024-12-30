
import os
import subprocess
import shlex
import json
import networkx as nx

def run_command(cmd):
    FNULL = open(os.devnull, "w")
    solc_p = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=FNULL)
    return solc_p.communicate()[0].decode("utf-8", "strict")

def get_source_ast(filename, solc_version):
    cmd = f"solc-select use {solc_version}"
    out = run_command(cmd)
    cmd = "solc --combined-json ast %s" % filename
    out = run_command(cmd)
    out = json.loads(out)
    return out["sources"]

def run_solc_get_abi(sol_file_path, contract_name, solc_version):
    cmd = f"solc-select use {solc_version}"
    out = run_command(cmd)
    cmd = f"solc --combined-json abi {sol_file_path}"
    out = run_command(cmd)
    out = json.loads(out)
    contract = sol_file_path + ":" + contract_name
    abis = out["contracts"][contract]["abi"]
    if type(abis) == str:
        abis = json.loads(abis)
    abi_names = []
    for abi in abis:
        if abi["type"] == "function":
            abi_names.append(abi["name"])
    
    return abi_names

class SubgraphSplitter:
    def __init__(self) -> None:
        self.functions_calls_map = {} # contract_name => function_name => calls func
        self.calls_relationship = {} # contract_name => [calls relationship]

        self.contract_name_by_id = {}
        self.contract_id_by_name = {}
        self.linearized_base_contracts_id_by_name = {}

        self.call_graph = nx.DiGraph()


    def visit_node_08(self, node, current_contract=None, current_function=None):
        if node is None:
            return 
        
        if node.get("nodeType") == "FunctionCall" and node.get("kind") == "functionCall":
            if current_function:
                if node["expression"]["nodeType"] == "Identifier":
                    called_function = node["expression"]["name"]
                    if called_function != "require" and called_function != "assert":
                        self.calls_relationship[current_contract].append((current_function, called_function, "Identifier"))

                # elif node["expression"]["nodeType"] == "MemberAccess":
                #     called_function = node["expression"]["memberName"]
                #     self.calls_relationship[current_contract].append((current_function, called_function, "MemberAccess"))


        elif node.get("nodeType") == "FunctionDefinition":
            if current_contract:
                function_name = node["name"]
                if function_name == "":
                    function_name = node["kind"]

                self.functions_calls_map[current_contract][function_name] = []
                current_function = function_name

        elif node.get("nodeType") == "ContractDefinition":
            if node["contractKind"] != "contract":
                return 
            contract_name = node["name"]
            self.functions_calls_map[contract_name] = {}
            self.calls_relationship[contract_name] = []
            current_contract = contract_name

            self.contract_id_by_name[contract_name] = node["id"]
            self.contract_name_by_id[node["id"]] = contract_name
            self.linearized_base_contracts_id_by_name[contract_name] = node["linearizedBaseContracts"]

        for child in node.values():
            if isinstance(child, list):
                for item in child:
                    if isinstance(item, dict):
                        self.visit_node_08(item, current_contract, current_function)
            elif isinstance(child, dict):
                self.visit_node_08(child, current_contract, current_function)



    def visit_node(self, node, current_contract=None, current_function=None):
        if node is None:
            return

        if node.get("name") == 'FunctionCall':
            if current_function:
                if node["children"][0]["name"] == "Identifier":
                    called_function = node["children"][0]["attributes"]["value"]
                    self.calls_relationship[current_contract].append((current_function, called_function))

        elif node.get("name") == "FunctionDefinition":
            function_name = node["attributes"]["name"]
            if function_name == "":
                function_name = "fallback"
            # self.functions_calls_map[function_name] = []
            self.functions_calls_map[current_contract][function_name] = []
            current_function = function_name

        elif node.get("name") == "ContractDefinition":
            contract_name = node["attributes"]["name"]
            self.functions_calls_map[contract_name] = {}
            self.calls_relationship[contract_name] = []
            current_contract = contract_name

        for child in node.values():
            if isinstance(child, list):
                for item in child:
                    if isinstance(item, dict):
                        self.visit_node(item, current_contract, current_function)
            elif isinstance(child, dict):
                self.visit_node(child, current_contract, current_function)

    def find_callee_contract_name(self, contract_name, callee):
        linearized_base_contract_ids = self.linearized_base_contracts_id_by_name[contract_name]
        for base_contract_id in linearized_base_contract_ids:
            if base_contract_id not in self.contract_name_by_id.keys():
                continue
            base_contracts_name = self.contract_name_by_id[base_contract_id]
            if callee in self.functions_calls_map[base_contracts_name].keys():
                return base_contracts_name
        
        return None

    def construct_inter_contracts_call_graph(self):
        for contract_name in self.functions_calls_map:
            for function_name in self.functions_calls_map[contract_name]:
                self.call_graph.add_node(f"{contract_name}:{function_name}")

        for contract_name in self.calls_relationship:
            for call in self.calls_relationship[contract_name]:
                caller, callee, type = call
                callee_contract_name = self.find_callee_contract_name(contract_name, callee)
                if callee_contract_name != None:
                    self.call_graph.add_edge(f"{contract_name}:{caller}", f"{callee_contract_name}:{callee}")

    
    def find_reachable_nodes(self, start_node):
        reachable_nodes = list(nx.dfs_tree(self.call_graph, source=start_node).nodes())
        return reachable_nodes
    
    def mask_abi_names(self, contract_name, abi_names):
        masked_abis = []
        for abi_func_name in abi_names:
            base_contracts_name = self.find_callee_contract_name(contract_name, abi_func_name)
            if base_contracts_name != None:
                masked_abis.append(f"{base_contracts_name}:{abi_func_name}")

        return masked_abis

    def run(self, sol_file_path, contract_name, solc_version):
        if solc_version.startswith("0.8"):
            source_list = get_source_ast(sol_file_path, solc_version)
            for k in source_list:
                ast = source_list[k]["AST"]

                self.visit_node_08(ast)
                self.construct_inter_contracts_call_graph()
                
            abi_names = run_solc_get_abi(sol_file_path, contract_name, solc_version)
            masked_abis = self.mask_abi_names(contract_name, abi_names)
 
            subgraphs = []
            for masked_abi_name in masked_abis:
                reachable_nodes = self.find_reachable_nodes(masked_abi_name)
                subgraphs.append(reachable_nodes)
            return subgraphs
            
        
        # source_list = get_source_ast(sol_file_path, solc_version)
        # for k in source_list:
        #     ast = source_list[k]["AST"]

        #     self.visit_node(ast)

        # self.construct_call_graph(contract_name)
        # subgraphs = self.partition_call_graph()

        # return subgraphs


# sol_file_path = "demo.sol"
# contract_name = "Test"
# solc_version = "0.8.5"
# subgraphSplitter = SubgraphSplitter()
# subgraphSplitter.run(sol_file_path, contract_name, solc_version)


sol_file_path = "/home/szz/Desktop/LLM/dataset/08/05a7328f81fb1ed77a405cac4621d2eb33530f00_CollageBots.sol"
contract_name = "CollageBots"
solc_version = "0.8.5"
subgraphSplitter = SubgraphSplitter()
subgraphSplitter.run(sol_file_path, contract_name, solc_version)
