
import json
import os
import re
import copy

def count(json_file_path, res, sol_file_name):
    if os.path.exists(json_file_path):
        with open(json_file_path, "r") as f:
            data = json.load(f)

        res["count"] += 1
        res["time_all"] += float(data["time"])

        if len(data["analysis"]["div_in_path"]) > 0:
            res["vul"]["div_in_path"] += 1
            res["list"]["div_in_path"].append(sol_file_name)
        if len(data["analysis"]["operator_order_issue"]) > 0:
            res["vul"]["operator_order_issue"] += 1
            res["list"]["operator_order_issue"].append(sol_file_name)
        if len(data["analysis"]["indivisible_amount"]) > 0:
            res["vul"]["indivisible_amount"] += 1
            res["list"]["indivisible_amount"].append(sol_file_name)
        if len(data["analysis"]["precision_loss_trend"]) > 0:
            res["vul"]["precision_loss_trend"] += 1
            res["list"]["precision_loss_trend"].append(sol_file_name)
        if len(data["analysis"]["exchange_problem"]) > 0:
            res["vul"]["exchange_problem"] += 1
            res["list"]["exchange_problem"].append(sol_file_name)
        if len(data["analysis"]["exchange_rounding"]) > 0:
            res["vul"]["exchange_rounding"] += 1
            res["list"]["exchange_rounding"].append(sol_file_name)
        if len(data["analysis"]["profit_opportunity"]) > 0:
            res["vul"]["profit_opportunity"] += 1
            res["list"]["profit_opportunity"].append(sol_file_name)

        return res, True
    else:
        return res, False

res = {
    "time_all": 0,
    "count": 0,
    "time_avg": 0,
    "error": 0,

    "vul": {
        "div_in_path": 0, 
        "operator_order_issue": 0, 
        "indivisible_amount": 0, 
        "precision_loss_trend": 0, 
        "exchange_problem": 0, 
        "exchange_rounding": 0, 
        "exchange_rounding": 0, 
        "profit_opportunity": 0,
    },
    "list": {
        "div_in_path": [], 
        "operator_order_issue": [], 
        "indivisible_amount": [], 
        "precision_loss_trend": [], 
        "exchange_problem": [], 
        "exchange_rounding": [], 
        "exchange_rounding": [], 
        "profit_opportunity": [],

        "error": [], 
    }
}


ex_dataset_dir_path = "Large_Scale_Dataset_and_Res"
csv_file_path = "large_dataset_without_95.csv"
not_exists = []

with open(csv_file_path, "r") as f:
    lines = f.readlines()

for line in lines:
    sol_file_name, contract_name, solc_version = line.strip().split(",")
    
    version = "".join(re.findall(r"(\d)\.(\d)", solc_version)[0])
    json_file_name = f"{sol_file_name}:{contract_name}.json"
    json_file_path = f"{ex_dataset_dir_path}/{json_file_name}"


    # evm_file_name = f"{sol_file_name}:{contract_name}.evm"
    # ex_evm_file_path = f"{ex_dataset_dir_path}/{evm_file_name}"

    if not os.path.exists(json_file_path):
        res["error"] += 1
        res["list"]["error"].append(sol_file_name)
    else:
        res, isExists = count(json_file_path, res, sol_file_name)

    if not isExists:
        not_exists.append(sol_file_name)


res["time_avg"] = res["time_all"] / res["count"]

with open(f"large.json", "w") as f:
    json.dump(res, f, indent=4)


