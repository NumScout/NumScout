import logging
import os
import re
import subprocess

import six
from crytic_compile import CryticCompile, InvalidCompilation

import global_params
from inputter.slot_map import SlotMap
from inputter.source_map import SourceMap


class InputHelper:
    # not support bytecode yet
    BYTECODE = 0
    SOLIDITY = 1

    def __init__(self, input_type, **kwargs):
        self.input_type = input_type
        self.target = global_params.SOURCE

        if input_type == InputHelper.SOLIDITY:
            attr_defaults = {
                "source": None,
                "evm": False,
                "root_path": "",
                "compiled_contracts": [],
                "compilation_err": False,
            }

        for attr, default in six.iteritems(attr_defaults):
            val = kwargs.get(attr, default)
            if val == None:
                raise Exception("'%s' attribute can't be None" % attr)
            else:
                setattr(self, attr, val)

    def get_inputs(self, targetContracts=None):
        inputs = []

        # adapt to the new version of crytic which supports solc 0.8.x
        # make NFTGuard capable of analyzing contracts with a higher solc version
        contracts = self._get_compiled_contracts()

        # mark contract number in a Solidity file
        global_params.CONTRACT_COUNT = len(contracts)
        self._prepare_disasm_files_for_analysis(contracts)
        for contract, _ in contracts:
            c_source, cname = contract.split(":")

            if targetContracts is not None and cname not in targetContracts:
                continue
            c_source = re.sub(self.root_path, "", c_source)
            if self.input_type == InputHelper.SOLIDITY:
                source_map = SourceMap(contract, self.source, "solidity")

                ### 
                # slot_map = SlotMap(contract, self.source)

            disasm_file = self._get_temporary_files(contract)["disasm"]
            inputs.append(
                {
                    "contract": contract,
                    "source_map": source_map,
                    "source": self.source,
                    "c_source": c_source,
                    "c_name": cname,
                    "disasm_file": disasm_file,

                    ###
                    # "slot_map": slot_map,
                }
            )
            logging.info("contract:" + contract)
        if targetContracts is not None and not inputs:
            raise ValueError("Targeted contracts weren't found in the source code!")
        return inputs

    def rm_tmp_files(self):
        self._rm_tmp_files_of_multiple_contracts(self.compiled_contracts)

    def _get_compiled_contracts(self):
        if not self.compiled_contracts:
            if self.input_type == InputHelper.SOLIDITY:
                self.compiled_contracts = self._compile_solidity()

        return self.compiled_contracts

    def _extract_bin_obj(self, com: CryticCompile):
        contracts = []
        contract2bin = {}

        units = com.compilation_units[self.target]

        for contract in units.contracts_names:
            contract2bin[contract] = units.bytecode_runtime(contract)
        for file in com.filenames:
            for contract in units.filename_to_contracts[file]:
                if units.bytecode_runtime(contract):
                    contracts.append(
                        ## not relative???
                        (file.relative + ":" + contract, contract2bin[contract])
                        # (file.absolute + ":" + contract, contract2bin[contract])
                    )

        return contracts

    def _compile_solidity(self):
        try:
            options = []
            logging.info("Compiling solidity...")

            com = CryticCompile(self.target)
            contracts = self._extract_bin_obj(com)

            libs = com.filenames.difference(
                com.compilation_units[self.target].contracts_names_without_libraries
            )
            return contracts
        except InvalidCompilation as err:
            if not self.compilation_err:
                logging.critical(
                    "Solidity compilation failed. Please use -ce flag to see the detail."
                )
            else:
                logging.critical("solc output:\n" + self.source)
                logging.critical(err)
                logging.critical("Solidity compilation failed.")
            exit(1)

    def _removeSwarmHash(self, evm):
        ### 
        # evm_without_hash = re.sub(r"a165627a7a72305820\S{64}0029$", "", evm)
        CBOR_length = evm[-4:]
        metadata_length = 4 + int(CBOR_length[-2:], 16) * 2
        evm_without_hash = evm[:-metadata_length]
        return evm_without_hash

    def _link_libraries(self, filename, libs):
        options = []
        for idx, lib in enumerate(libs):
            lib_address = "0x" + hex(idx + 1)[2:].zfill(40)
            options.append("--libraries %s:%s" % (lib, lib_address))
        com = CryticCompile(target=self.source, solc_args=" ".join(options))

        return self._extract_bin_obj(com)

    def _prepare_disasm_files_for_analysis(self, contracts):
        for contract, bytecode in contracts:
            self._prepare_disasm_file(contract, bytecode)

    def _prepare_disasm_file(self, target, bytecode):
        self._write_evm_file(target, bytecode)
        self._write_disasm_file(target)

    def _get_temporary_files(self, target):
        return {
            "evm": target + ".evm",
            "disasm": target + ".evm.disasm",
            "log": target + ".evm.disasm.log",
        }

    def _write_evm_file(self, target, bytecode):
        evm_file = self._get_temporary_files(target)["evm"]
        with open(evm_file, "w") as of:
            of.write(self._removeSwarmHash(bytecode))

    def _write_disasm_file(self, target):
        tmp_files = self._get_temporary_files(target)
        evm_file = tmp_files["evm"]
        disasm_file = tmp_files["disasm"]
        disasm_out = ""
        try:
            disasm_p = subprocess.Popen(
                ["evm", "disasm", evm_file], stdout=subprocess.PIPE
            )
            disasm_out = disasm_p.communicate()[0].decode("utf-8", "strict")
        except:
            logging.critical("Disassembly failed.")
            exit()

        with open(disasm_file, "w") as of:
            of.write(disasm_out)

    def _rm_tmp_files_of_multiple_contracts(self, contracts):
        for contract, _ in contracts:
            self._rm_tmp_files(contract)

    def _rm_tmp_files(self, target):
        tmp_files = self._get_temporary_files(target)
        if not self.evm:
            self._rm_file(tmp_files["evm"])
            self._rm_file(tmp_files["disasm"])
        self._rm_file(tmp_files["log"])

    def _rm_file(self, path):
        if os.path.isfile(path):
            os.unlink(path)
