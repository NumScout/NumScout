import re


class FunctionExtractor:
    def __init__(self) -> None:
        pass

    def find_matching_bracket(self, code, start_index):
        """找到与起始大括号匹配的结束大括号的索引"""
        open_brackets = 1
        for i in range(start_index + 1, len(code)):
            if code[i] == '{':
                open_brackets += 1
            elif code[i] == '}':
                open_brackets -= 1
            if open_brackets == 0:
                return i
        return -1  # 如果没有找到匹配的括号
    
    # def extract_contract_body(self, solidity_code, target_contract_name):
    #     """提取完整的合约代码，包括合约定义和所有内容"""
    #     # 匹配合约定义的正则表达式
    #     contract_pattern = re.compile(r'contract\s+' + re.escape(target_contract_name) + r'\s*(.*?)\{', re.DOTALL)
    #     match = contract_pattern.search(solidity_code)
    #     if match:
    #         start_index = match.end() - 1  # 合约体起始大括号的索引
    #         end_index = self.find_matching_bracket(solidity_code, start_index)
    #         if end_index != -1:
    #             return solidity_code[match.start():end_index+1]
    #     return None

    def extract_contract_bodys(self, solidity_code):
        """提取完整的合约代码，包括合约定义和所有内容"""
        # 匹配合约定义的正则表达式
        contract_map = {}
        contract_pattern = re.compile(r'contract\s+([a-zA-Z0-9_]*)\s*(.*?)\{')
        for match in contract_pattern.finditer(solidity_code):
            contract_name, _ = match.groups()
            start_index = match.end() - 1  # 合约体起始大括号的索引
            end_index = self.find_matching_bracket(solidity_code, start_index)
            if end_index != -1:
                full_contract = solidity_code[match.start():end_index+1]

            contract_map[contract_name] = full_contract

        return contract_map

    def extract_functions_with_body(self, contract_body):
        # 匹配函数定义的正则表达式（不包含函数体）
        function_pattern = re.compile(r'function\s*([a-zA-Z0-9_]*)\s*\(([^)]*)\)\s*([^;]*?)\{', re.DOTALL)

        comment_pattern = re.compile(r'/\*\*([^*]|\*[^/])*?\*/$', re.DOTALL)

        # 搜索所有的函数定义
        function_map = {}
        for match in function_pattern.finditer(contract_body):
            name, params, modifiers = match.groups()
            start_index = match.end() - 1  # 函数体起始大括号的索引
            end_index = self.find_matching_bracket(contract_body, start_index)
            if end_index != -1:
                full_function = contract_body[match.start():end_index+1]
                if name == "":  # 匹配无名函数
                    name = "fallback"

                preceding_text = contract_body[:match.start()].rstrip()
                comment_match = comment_pattern.search(preceding_text)
                if comment_match:
                    # comment_start = comment_match.start()
                    full_function = contract_body[comment_match.start():end_index+1]
                

                function_map[name] = full_function

        return function_map
    
    def extract_special_function_with_body(
        self, 
        special_function_name, 
        special_function_pattern, 
        contract_body, 
        function_map
    ):
        match = special_function_pattern.search(contract_body)
        if match:
            start_index = match.end() - 1
            end_index = self.find_matching_bracket(contract_body, start_index)
            if end_index != -1:
                special_function_body = contract_body[match.start():end_index+1]
                function_map[special_function_name] = special_function_body

        return function_map
    
    def extract_special_functions_with_body_08(self, contract_body, function_map):
        constructor_pattern = re.compile(r'constructor\s*\(([^)]*)\)\s*([^;]*?)\{', re.DOTALL)
        function_map = self.extract_special_function_with_body(
            "constructor", 
            constructor_pattern, 
            contract_body, 
            function_map
        )

        fallback_pattern = re.compile(r'fallback\s*\(([^)]*)\)\s*([^;]*?)\{', re.DOTALL)
        function_map = self.extract_special_function_with_body(
            "fallback", 
            fallback_pattern, 
            contract_body, 
            function_map
        )

        receive_pattern = re.compile(r'receive\s*\(([^)]*)\)\s*([^;]*?)\{', re.DOTALL)
        function_map = self.extract_special_function_with_body(
            "receive", 
            receive_pattern, 
            contract_body, 
            function_map
        )

        return function_map

    def read_sol_file(self, sol_file_path):
        with open(sol_file_path, 'r', encoding='utf-8') as file:
            code_content = file.read().strip()
        return code_content

    def run(self, sol_file_path, contract_name, solc_version):
        function_map_by_contract = {}
        solidity_code = self.read_sol_file(sol_file_path)
        contract_map = self.extract_contract_bodys(solidity_code)
        for contract_name in contract_map:
            function_map = self.extract_functions_with_body(contract_map[contract_name])
            if solc_version.startswith("0.8"):
                function_map = self.extract_special_functions_with_body_08(contract_map[contract_name], function_map)
            # return function_map
            function_map_by_contract[contract_name] = function_map
        # else:
        #     print("No contract found.")
        #     return "extract error"
        return function_map_by_contract


# 示例智能合约代码
# sol_file_path = "/home/szz/Desktop/LLM/dataset/04/1f4dce2bf4345fb630a185483699015aa6961f37_GemsPlay.sol"
# contract_name = "GemsPlay"
sol_file_path = "/home/szz/Desktop/LLM/dataset/08/05a7328f81fb1ed77a405cac4621d2eb33530f00_CollageBots.sol"
contract_name = "CollageBots"
solc_version = "0.8.5"
functionExtractor = FunctionExtractor()
functionExtractor.run(sol_file_path, contract_name, solc_version)
