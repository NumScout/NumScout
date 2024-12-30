import time
import global_params
import json
import logging
from rich.console import Console
from rich.table import Table
from defect_identifier.defect import (
    DivInPath,
    OperatorOrderIssue,
    IndivisibleAmount,
    PrecisionLossTrend,
    ExchangeProblem,
    ExchangeRounding,
    ProfitOpportunity
)

log = logging.getLogger(__name__)


class Identifier:
    @classmethod
    def detect_defects(
        self,
        instructions,
        results,
        g_src_map,
        visited_pcs,
        global_problematic_pcs,
        begin,
        g_disasm_file,
    ):
        """Analyzes defects and reports the final results."""
        if instructions:
            evm_code_coverage = float(len(visited_pcs)) / len(instructions.keys()) * 100
            results["evm_code_coverage"] = str(round(evm_code_coverage, 1))
            results["instructions"] = str(len(instructions.keys()))

            end = time.time()

            self.detect_div_in_path(self, results, g_src_map, global_problematic_pcs)
            self.detect_operator_order_issue(self, results, g_src_map, global_problematic_pcs)
            self.detect_indivisible_amount(self, results, g_src_map, global_problematic_pcs)
            self.detect_precision_loss_trend(self, results, g_src_map, global_problematic_pcs)
            self.detect_exchange_problem(self, results, g_src_map, global_problematic_pcs)
            self.detect_exchange_rounding(self, results, g_src_map, global_problematic_pcs)
            self.detect_profit_opportunity(self, results, g_src_map, global_problematic_pcs)

            ### 
            # *All Defects to be detectd...
            # self.detect_violation(self, results, g_src_map, global_problematic_pcs)
            # self.detect_reentrancy(self, results, g_src_map, global_problematic_pcs)
            # self.detect_proxy(self, results, g_src_map, global_problematic_pcs)
            # self.detect_unlimited_minting(
            #     self, results, g_src_map, global_problematic_pcs
            # )
            # self.detect_public_burn(self, results, g_src_map, global_problematic_pcs)

            # defect_table = Table()

            # defect_table.add_column(
            #     "Defect", justify="right", style="dim", no_wrap=True
            # )
            # defect_table.add_column("Status", style="green")
            # defect_table.add_column("Location", justify="left", style="cyan")

            # defect_table.add_row(
            #     "Risky Mutable Proxy", str(proxy.is_defective()), str(proxy)
            # )
            # defect_table.add_row(
            #     "ERC-721 Reentrancy", str(reentrancy.is_defective()), str(reentrancy)
            # )
            # defect_table.add_row(
            #     "Unlimited Minting",
            #     str(unlimited_minting.is_defective()),
            #     str(unlimited_minting),
            # )
            # defect_table.add_row(
            #     "Missing Requirements", str(violation.is_defective()), str(violation)
            # )
            # defect_table.add_row(
            #     "Public Burn", str(public_burn.is_defective()), str(public_burn)
            # )

            # param_table = Table()
            # param_table.add_column("Time", justify="left", style="cyan", no_wrap=True)
            # param_table.add_column(
            #     "Code Coverage", justify="left", style="yellow", no_wrap=True
            # )
            # param_table.add_row(
            #     str(round(end - begin, 1)), str(round(evm_code_coverage, 1))
            # )

            # instruct = Table()
            # instruct.add_column(
            #     "Total Instructions",
            #     justify="left",
            #     style="cyan",
            #     no_wrap=True,
            #     width=20,
            # )

            # instruct.add_row(results["instructions"])

            # state_table = Table.grid(expand=True)
            # state_table.add_column(justify="center")
            # state_table.add_row(param_table)
            # state_table.add_row(instruct)

            # reporter = Table(title="NFTGuard GENESIS v0.0.1")
            # reporter.add_column("Defect Detection", justify="center")
            # reporter.add_column("Execution States", justify="center")
            # reporter.add_row(defect_table, state_table)

            # console = Console()
            # console.print(reporter)

        else:
            log.info("\t  No Instructions \t")
            results["evm_code_coverage"] = "0/0"
        self.closing_message(begin, g_disasm_file, results, end)
        ### 
        # return results, self.defect_found(g_src_map)
        return results, self.defect_found(g_src_map, results)
    

    def detect_div_in_path(self, results, g_src_map, global_problematic_pcs):
        global div_in_path
        pcs = global_problematic_pcs["div_in_path"]
        div_in_path = DivInPath(g_src_map, pcs)

        if g_src_map:
            results["analysis"]["div_in_path"] = div_in_path.get_warnings()
        else:
            results["analysis"]["div_in_path"] = div_in_path.is_defective()
        results["bool_defect"]["div_in_path"] = div_in_path.is_defective()

    def detect_operator_order_issue(self, results, g_src_map, global_problematic_pcs):
        global operator_order_issue
        pcs = global_problematic_pcs["operator_order_issue"]
        operator_order_issue = OperatorOrderIssue(g_src_map, pcs)

        if g_src_map:
            results["analysis"]["operator_order_issue"] = operator_order_issue.get_warnings()
        else:
            results["analysis"]["operator_order_issue"] = operator_order_issue.is_defective()
        results["bool_defect"]["operator_order_issue"] = operator_order_issue.is_defective()

    def detect_indivisible_amount(self, results, g_src_map, global_problematic_pcs):
        global indivisible_amount
        pcs = []
        if not global_problematic_pcs["extract_all_eth"]:
            for x in global_problematic_pcs["indivisible_amount"]:
                pcs.append(x)
        
        if not global_problematic_pcs["extract_all_token"]:
            for x in global_problematic_pcs["indivisible_amount_token"]:
                pcs.append(x)
        indivisible_amount = IndivisibleAmount(g_src_map, pcs)

        if g_src_map:
            results["analysis"]["indivisible_amount"] = indivisible_amount.get_warnings()
        else:
            results["analysis"]["indivisible_amount"] = indivisible_amount.is_defective()
        results["bool_defect"]["indivisible_amount"] = indivisible_amount.is_defective()


    def detect_precision_loss_trend(self, results, g_src_map, global_problematic_pcs):
        global precision_loss_trend
        pcs = global_problematic_pcs["precision_loss_trend"]
        precision_loss_trend = PrecisionLossTrend(g_src_map, pcs)

        if g_src_map:
            results["analysis"]["precision_loss_trend"] = precision_loss_trend.get_warnings()
        else:
            results["analysis"]["precision_loss_trend"] = precision_loss_trend.is_defective()
        results["bool_defect"]["precision_loss_trend"] = precision_loss_trend.is_defective()


    def detect_exchange_problem(self, results, g_src_map, global_problematic_pcs):
        global exchange_problem
        pcs = global_problematic_pcs["exchange_problem"]
        exchange_problem = ExchangeProblem(g_src_map, pcs)

        if g_src_map:
            results["analysis"]["exchange_problem"] = exchange_problem.get_warnings()
        else:
            results["analysis"]["exchange_problem"] = exchange_problem.is_defective()
        results["bool_defect"]["exchange_problem"] = exchange_problem.is_defective()

    def detect_exchange_rounding(self, results, g_src_map, global_problematic_pcs):
        global exchange_rounding
        pcs = global_problematic_pcs["exchange_rounding"]
        exchange_rounding = ExchangeRounding(g_src_map, pcs)

        if g_src_map:
            results["analysis"]["exchange_rounding"] = exchange_rounding.get_warnings()
        else:
            results["analysis"]["exchange_rounding"] = exchange_rounding.is_defective()
        results["bool_defect"]["exchange_rounding"] = exchange_rounding.is_defective()


    def detect_profit_opportunity(self, results, g_src_map, global_problematic_pcs):
        global profit_opportunity
        pcs = global_problematic_pcs["profit_opportunity"]
        profit_opportunity = ProfitOpportunity(g_src_map, pcs)

        if g_src_map:
            results["analysis"]["profit_opportunity"] = profit_opportunity.get_warnings()
        else:
            results["analysis"]["profit_opportunity"] = profit_opportunity.is_defective()
        results["bool_defect"]["profit_opportunity"] = profit_opportunity.is_defective()


    def log_info():
        global reentrancy
        global violation
        global proxy
        global unlimited_minting
        global public_burn

        defects = [reentrancy, violation, proxy, unlimited_minting, public_burn]

        for defect in defects:
            s = str(defect)
            if s:
                log.info(s)
        
    def defect_found(g_src_map, results):
        
        if (results["bool_defect"]["div_in_path"]
            or results["bool_defect"]["operator_order_issue"]
            or results["bool_defect"]["indivisible_amount"]
            or results["bool_defect"]["precision_loss_trend"]
            or results["bool_defect"]["exchange_problem"]
            or results["bool_defect"]["exchange_rounding"]
            or results["bool_defect"]["profit_opportunity"]
        ):
            return 1
        return 0


    def closing_message(begin, g_disasm_file, results, end):
        results["time"] = str(end - begin)
        # write down extra contract info...
        results["address"] = global_params.CONTRACT_ADDRESS
        results["contract_count"] = global_params.CONTRACT_COUNT
        results["storage_var_count"] = global_params.STORAGE_VAR_COUNT
        results["pub_fun_count"] = global_params.PUB_FUN_COUNT

        log.info("\t====== Analysis Completed ======")
        if global_params.STORE_RESULT:
            result_file = g_disasm_file.split(".evm.disasm")[0] + ".json"
            with open(result_file, "w") as of:
                of.write(json.dumps(results, indent=1))
            log.info("Wrote results to %s.", result_file)




