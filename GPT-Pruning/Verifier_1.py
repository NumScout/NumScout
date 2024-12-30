from Chat import Chat

class Verifier_1:
    def __init__(self, chat: Chat) -> None:
        self.chat = chat

    def save_res(self, res_file_path, analysis_res):
        with open(res_file_path, "w", encoding="utf-8") as f:
            f.write(analysis_res)

    def run(self, contract_name: str, related_functions: list, code: str, sol_file_path: str, res_file_path: str):
        system_prompt = "You are a smart contract auditor. You will be asked questions related to code properties. You can mimic answering them in the background five times and provide me with the most frequently appearing answer. Furthermore, please strictly adhere to the output format specified in the question; there is no need to explain your answer."
        # system_prompt = ""

        user_prompt = f"""
You are a helpful and honest code reviewer working with your partner. Your responsibility is to check whether your partner's classification results are reasonable and accurate. Below, I define your abilities, your responsibilities, and your constraints. You should consider all constraints and facts provided in the code.

# Abilities
1. You are an excellent smart contract code reviewer.
2. You are familiar with smart contract function calls.

# Responsibilities
1. You have to analyze the internal calling relationships of these provided public functions.
2. You have to check whether the function and its calling functions actually perform numerical operations on the amount of tokens or ether directly.
3. If you are sure that the function has direct impact on the token or ether changes, it means that your partner classification is correct, otherwise you think it is wrong.
4. Functions that indirectly affect the amount of tokens or ethers are unrelated functions and need to be classified as "wrong". For example, setting or getting transaction-related variables does not directly cause changes in account balances, so it is considered an unrelated function.

# Constraints
1. Your response has to be in this JSON format without any other content: {{"correct": [...], "wrong": [...]}}.
2. Do not add functions that are not in the provided related public functions list. Do not omit or have overlapping functions in the two parts.

The list of related public abi functions of the target contract "{contract_name}" provided by your partner is as follows: {related_functions}

The code I provide is:
```Solidity
{code}
```
"""
        analysis_res = self.chat.analyze_issue_with_gpt4(system_prompt, user_prompt)

        if analysis_res != "error":
            self.save_res(res_file_path, analysis_res)
            print(f"已完成对文件 '{sol_file_path}' 的related验证。")
        else:
            print(f"文件 '{sol_file_path}' 的分析失败。")
        
        return analysis_res

        



