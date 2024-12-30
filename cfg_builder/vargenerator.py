class Generator:
    """Generate variables and identifiers for symbolic execution"""

    def __init__(self):
        self.countstack = 0
        self.countdata = 0
        self.count = 0
        self.sha3_count = 0
        self.gas_count = 0
        self.mem_count = 0
        self.address_count = 0
        self.return_data_count = 0
        self.dscall_count = 0
        self.msize_count = 0

    def gen_stack_var(self):
        self.countstack += 1
        return "s" + str(self.countstack)

    # def gen_data_var(self):
    #     self.countdata += 1
    #     return "Id_dataload_" + str(self.countdata)

    def gen_calldataload_var(self, position):
        # self.countdata += 1
        # return "Id_" + str(self.countdata)
        return "calldata_" + str(position)
    
    def gen_data_size(self):
        return "Id_size"

    def gen_mem_var(self, address):
        # return "mem_" + str(address)
        self.mem_count += 1
        return "mem_%s_%s" % (str(address), str(self.mem_count))

    def gen_arbitrary_var(self):
        self.count += 1
        return "some_var_" + str(self.count)

    def gen_arbitrary_address_var(self):
        self.address_count += 1
        return "some_address_" + str(self.address_count)

    # def gen_owner_store_var(self, position, var_name=""):
    #     return "Ia_store-%s-%s" % (str(position), var_name)
    def gen_store_var(self, position):
        return "Ia_store-%s" % (str(position))

    def gen_gas_var(self):
        self.gas_count += 1
        return "gas_" + str(self.gas_count)

    def gen_gas_price_var(self):
        return "Ip"

    def gen_address_var(self):
        return "Ia"

    def gen_caller_var(self):
        return "Is"

    def gen_origin_var(self):
        return "Io"

    def gen_balance_var(self, address):
        return "balance_" + str(address)

    def gen_code_var(self, address, position, bytecount):
        return "code_" + str(address) + "_" + str(position) + "_" + str(bytecount)

    def gen_code_size_var(self, address):
        return "code_size_" + str(address)
    
    def gen_calldata_size(self):
        return "calldata_size"
    
    def gen_sha3_var(self):
        self.sha3_count += 1
        return "sha3_" + str(self.sha3_count)

    def gen_returndatasize_var(self):
        return "return_data_size"
    
    def gen_blockhash_var(self, blocknumber):
        return "blockhash_" + str(blocknumber)
    
    def gen_return_data(self):
        self.return_data_count += 1
        return "return_data_" + str(self.return_data_count)
    
    def gen_DSCALL_res_var(self):
        return "dscall_res_" + str(self.dscall_count)
    
    def gen_msize_var(self):
        return "msize_" + str(self.msize_count)
