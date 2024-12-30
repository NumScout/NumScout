
from SubgraphSplitter import SubgraphSplitter
from FunctionExtractor import FunctionExtractor

class CodeSplitter:
    def __init__(self, sol_file_path, contract_name, solc_version) -> None:
        self.sol_file_path = sol_file_path
        self.contract_name = contract_name
        self.solc_version = solc_version

        self.subgraphSplitter = SubgraphSplitter()
        self.functionExtractor = FunctionExtractor()
    
    def calculate_total_length(self, unique_functions, function_map_by_contract):
        total_length = 0
        for func in unique_functions:
            contract_name, func_name = func.split(":")
            total_length += len(function_map_by_contract[contract_name][func_name])

        return total_length

    def merge_subgraphs_based_on_threshold(self, threshold, subgraphs, function_map_by_contract):
        partitions = []
        for subgraph in subgraphs:
            placed = False
            for i in range(len(partitions)):
                tmp_partition = list(set(partitions[i] + subgraph))
                total_length = self.calculate_total_length(tmp_partition, function_map_by_contract)
                if total_length <= threshold:
                    partitions[i] = tmp_partition
                    placed = True
                    break

            if not placed:
                partitions.append(subgraph)

        return partitions


    def read_sol_file(self, sol_file_path):
        with open(sol_file_path, 'r', encoding='utf-8') as file:
            code_content = file.read().strip()
        return code_content
    
    def replace_sol_code(self, partition, solidity_code, function_map_by_contract):
        for contract_name in function_map_by_contract:
            for func_name in function_map_by_contract[contract_name]:
                if f"{contract_name}:{func_name}" not in partition:
                    solidity_code = solidity_code.replace(function_map_by_contract[contract_name][func_name], "")
        
        return solidity_code

    def replace_all(self, solidity_code, function_map_by_contract):
        for contract_name in function_map_by_contract:
            for func_name in function_map_by_contract[contract_name]:
                solidity_code = solidity_code.replace(function_map_by_contract[contract_name][func_name], "")
        
        print(f"[+] replace all len is {len(solidity_code)}")
        return solidity_code

    def run(self):
        subgraphs = self.subgraphSplitter.run(self.sol_file_path, self.contract_name, self.solc_version)
        function_map_by_contract = self.functionExtractor.run(self.sol_file_path, self.contract_name, self.solc_version)

        partitions = self.merge_subgraphs_based_on_threshold(20000, subgraphs, function_map_by_contract)

        solidity_code = self.read_sol_file(sol_file_path)
        print(f"[+] all code len is {len(solidity_code)}")
        
        replace_all = self.replace_all(solidity_code, function_map_by_contract)
        
        count = 1
        for partition in partitions:
            replaced_content = self.replace_sol_code(partition, solidity_code, function_map_by_contract)
            print(len(replaced_content))
            # with open(f"./split_Res/{count}.sol", "w") as f:
            #     f.write(replaced_content)
            count += 1
            


# sol_file_path = "/home/szz/Desktop/LLM/dataset/04/1f4dce2bf4345fb630a185483699015aa6961f37_GemsPlay.sol"
# contract_name = "GemsPlay"
# solc_version = "0.4.22"
sol_file_path = "/home/szz/Desktop/LLM/dataset/08/05a7328f81fb1ed77a405cac4621d2eb33530f00_CollageBots.sol"
contract_name = "CollageBots"
solc_version = "0.8.5"
# sol_file_path = "/home/szz/Desktop/LLM/demo.sol"
# contract_name = "Test"
# solc_version = "0.8.5"
codeSplitter = CodeSplitter(sol_file_path, contract_name, solc_version)
codeSplitter.run()






