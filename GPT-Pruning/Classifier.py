from Chat import Chat

class Classifier:
    def __init__(self, chat: Chat) -> None:
        self.chat = chat

    def save_res(self, res_file_path: str, analysis_res: str):
        with open(res_file_path, "w", encoding="utf-8") as f:
            f.write(analysis_res)

    def run(self, contract_name: str, abi_names: list, code: str, sol_file_path: str, res_file_path: str):
        system_prompt = "You are a smart contract auditor. You will be asked questions related to code properties. You can mimic answering them in the background five times and provide me with the most frequently appearing answer. Furthermore, please strictly adhere to the output format specified in the question; there is no need to explain your answer."

        user_prompt = f"""
You need to answer the following questions: In the code, which public functions are directly related to changes in token balances or account ether for users or the contract itself, and which are not? 
Think step by step: First, analyze which functions will perform numerical operations on the number of tokens or ethers and directly change the number of tokens or ethers. Then, analyze the calling relationships between functions, find which public functions in the given public function list will call these functions. Finally classify them as related or unrelated. Only consider functions that directly change token balance or account ether, and do not consider functions that indirectly affect.

Your response has to be in this JSON format without any other content: {{"related": [...], "unrelated": [...]}}.

All public abi functions of the target contract "{contract_name}" have been given: {abi_names}.
Do not add functions that are not in the list. Do not omit or have overlapping functions in the two parts.

The code I provide is:
```Solidity
{code}
```
"""
        analysis_res = self.chat.analyze_issue_with_gpt4(system_prompt, user_prompt)
        if analysis_res != "error":
            self.save_res(res_file_path, analysis_res)
            print(f"已完成对文件 '{sol_file_path}' 的分析。")
        else:
            print(f"文件 '{sol_file_path}' 的分析失败。")
        
        return analysis_res
        
    
