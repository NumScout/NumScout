import os
import subprocess
import shlex
import json
import re
import time

from Chat import Chat
from Classifier import Classifier
from Verifier_1 import Verifier_1
from Verifier_2 import Verifier_2
from Combiner import Combiner


def run_command(cmd):
    FNULL = open(os.devnull, "w")
    solc_p = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=FNULL)
    return solc_p.communicate()[0].decode("utf-8", "strict")

def run_solc_get_abi(sol_file_path, contract_name, solc_version):
    try:
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
    except:
        return None


def read_sol_file(sol_file_path):
    with open(sol_file_path, 'r', encoding='utf-8') as file:
        code_content = file.read().strip()
    return code_content

def write_sol_file(extract_sol_file_path, contract_body):
    with open(extract_sol_file_path, "w", encoding="utf-8") as f:
        f.write(contract_body)


def run_classifier(classifier: Classifier, abi_names: list, code: str, sol_file_path: str, res_file_path: str):
    classifier.run(abi_names, code, sol_file_path, res_file_path)

def load_classification_results(res_file_path):
    with open(res_file_path, "r", encoding="utf-8") as f:
        content = f.read().strip()
    
    try:
        classification_res = json.loads(content)
    except:

        classification_res = re.findall(r"(\{[\w\W]*?\})", content)[0]
        classification_res = json.loads(classification_res)
    
    related_functions = classification_res["related"]
    unrelated_functions = classification_res["unrelated"]
    return classification_res, related_functions, unrelated_functions
    

def load_verification_results(res_file_path):
    with open(res_file_path, "r", encoding="utf-8") as f:
        content = f.read().strip()

    try:
        res = json.loads(content)
    except:
        res = re.findall(r"(\{[\w\W]*?\})", content)[0]
        # res = json.loads(res)
        res = eval(res)
    
    correct = res["correct"]
    wrong = res["wrong"]
    return correct, wrong


def main():
    api_key = ""
    chat = Chat(api_key)


    classifier = Classifier(chat)
    verifier_1 = Verifier_1(chat)
    verifier_2 = Verifier_2(chat)
    combiner = Combiner(chat)

    dataset_dir_path = "95_Samples_Run/95_samples"
    cannot_compile = []

    with open("95_Samples_Run/95_samples.csv", "r") as f:
        lines = f.readlines()

    request_count = 0
    for line in lines:
        sol_file_name, contract_name, solc_version = line.strip().split(",")
        if solc_version.startswith("v"):
            solc_version = solc_version[1:]
        sol_file_path = f"{dataset_dir_path}/{sol_file_name}"
        abi_names = run_solc_get_abi(sol_file_path, contract_name, solc_version)
        if abi_names == None:
            print(f"[+] Cann't compile: {sol_file_name}")
            cannot_compile.append(sol_file_name)
            continue
        code = read_sol_file(sol_file_path)
        
        classification_dir_path = f"95_Samples_Run/95_Pruning_Result/Classification"
        res_file_path = f"{classification_dir_path}/{sol_file_name}:{contract_name}.txt"
        if not os.path.exists(res_file_path):
            classifier.run(contract_name, abi_names, code, sol_file_path, res_file_path)
            request_count += 1
            time.sleep(3)
        classification_res, related_functions, unrelated_functions = load_classification_results(res_file_path)

        verification_related_dir_path = f"95_Samples_Run/95_Pruning_Result/Verification_Related"
        res_file_path = f"{verification_related_dir_path}/{sol_file_name}:{contract_name}.txt"
        if not os.path.exists(res_file_path):
            verifier_1.run(contract_name, related_functions, code, sol_file_path, res_file_path)
            request_count += 1
            time.sleep(3)
        related_correct_functions, related_wrong_functions = load_verification_results(res_file_path)

        verification_unrelated_dir_path = f"95_Samples_Run/95_Pruning_Result/Verification_Unrelated"
        res_file_path = f"{verification_unrelated_dir_path}/{sol_file_name}:{contract_name}.txt"
        if not os.path.exists(res_file_path):
            verifier_2.run(contract_name, unrelated_functions, code, sol_file_path, res_file_path)
            request_count += 1
            time.sleep(3)
        unrelated_correct_functions, unrelated_wrong_functions = load_verification_results(res_file_path)

        combination_dir_path = f"95_Samples_Run/95_Pruning_Result/Combination"
        res_file_path = f"{combination_dir_path}/{sol_file_name}:{contract_name}.txt"
        if not os.path.exists(res_file_path):
            combiner.run(
                contract_name, 
                abi_names, 
                code, 
                classification_res, 
                related_correct_functions, 
                related_wrong_functions, 
                unrelated_correct_functions, 
                unrelated_wrong_functions, 
                sol_file_path, 
                res_file_path
            )
            request_count += 1
            time.sleep(3)
    
    print(f"[+] cannot_compile list: {len(cannot_compile)}")
    print(f"[+] api request count: {request_count}")


if __name__ == "__main__":
    main()


