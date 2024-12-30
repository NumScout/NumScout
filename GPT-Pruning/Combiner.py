from Chat import Chat

class Combiner:
    def __init__(self, chat: Chat) -> None:
        self.chat = chat

    def save_res(self, res_file_path: str, analysis_res: str):
        with open(res_file_path, "w", encoding="utf-8") as f:
            f.write(analysis_res)

    def run(
            self, 
            contract_name: str, 
            abi_names: list, 
            code: str, 
            classification_res: dict, 
            related_correct_functions: list, 
            related_wrong_functions: list, 
            unrelated_correct_functions: list, 
            unrelated_wrong_functions: list, 
            sol_file_path: str, 
            res_file_path: str
    ):
        system_prompt = "You are a smart contract auditor. You will be asked questions related to code properties. You can mimic answering them in the background five times and provide me with the most frequently appearing answer. Furthermore, please strictly adhere to the output format specified in the question; there is no need to explain your answer."

        user_prompt = f"""
You are a helpful and honest code reviewer and work with your partners. Your responsibility is to make a final judgment by considering the results of one Classifier and two Verifiers. I will provide all the information about the code and the result from your partner. 

After reviewing the result, You should make the final analysis and judgment.
1. Do NOT just combine the results simply, do your own analysis and reasoning.
2. You have to analyze the contradiction function between the Classifier's results and the Verifiers' results, and determine whether the contradiction function is actually related to the change in the amount of tokens or ether directly.
3. If you are sure that the function has direct impact on the token or ether changes, you should group it into "related" functions, otherwise it is an "unrelated" function.
4. Your response has to be in this JSON format without any other content: {{"related": [...], "unrelated": [...]}}.
5. Do not add functions that are not in the provided related public functions list. Do not omit or have overlapping functions in the two parts.

I will provide the code and thre result from your partner.

The following are all public abi function names of the target contract "{contract_name}":
{abi_names}.

# Classifier's result:
{classification_res}

# Verifiers_1's result:
For the related functions considered by the Classifier, Verifiers_1 believes that some of these functions are indeed directly related: {related_correct_functions}, but the other part is not related: {related_wrong_functions}.

# Verifiers_2's result:
For the unrelated functions considered by the Classifier, Verifiers_2 believes that some of these functions are indeed unrelated: {unrelated_correct_functions}, but the other part is actually directly related: {unrelated_wrong_functions}

The code I provide is:
```Solidity
{code}
```
"""
        analysis_res = self.chat.analyze_issue_with_gpt4(system_prompt, user_prompt)
        if analysis_res != "error":
            self.save_res(res_file_path, analysis_res)
            print(f"已完成对文件 '{sol_file_path}' 的合并。")
        else:
            print(f"文件 '{sol_file_path}' 的分析失败。")
        
        return analysis_res
        
    
