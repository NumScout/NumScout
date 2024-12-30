from web3 import Web3
import json

SERVER_IP  = "127.0.0.1"
GETH_PORT  = "8545"

web3 = Web3(Web3.HTTPProvider(f'http://{SERVER_IP}:{GETH_PORT}')) 
assert web3.is_connected()

# Make sure both accounts have enough ether
owner_key = "0x..."
user_key = "0x..."
gas_price = 5
gas_limit = 5000000
owner_account = web3.eth.account.from_key(owner_key)
user_account = web3.eth.account.from_key(user_key)
print("[+] owner:", owner_account.address)

with open("bytecode", "r") as f:
    code = f.read()
with open("abi.json", "r") as f:
    abi = json.load(f)

print("[+] Start: deploy")
newContract = web3.eth.contract(abi=abi,bytecode=code)
construct_txn = newContract.constructor().buildTransaction({
    'from': owner_account.address,
    'nonce': web3.eth.getTransactionCount(owner_account.address),
    'gas': gas_limit,
    'gasPrice': web3.toWei(gas_price, "gwei"),
    "value": 0,
})

signed_tx = owner_account.signTransaction(construct_txn)
tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction).hex()
tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash)
# print(tx_receipt)
assert(tx_receipt['status'] == 1)
print("[+] Done: deploy")

contract_address = tx_receipt.contractAddress
contract = web3.eth.contract(address=contract_address, abi=abi)
print("[+] contract address:", contract_address)

print("[+] Start: changeSale")
tx = contract.functions.changeSale(True).buildTransaction({
    "from": owner_account.address,
    "value": 0,
    'gasPrice': web3.toWei(gas_price, "gwei"),
    "gas": gas_limit,
    "nonce": web3.eth.getTransactionCount(owner_account.address),
})
signed_tx = owner_account.signTransaction(tx)
tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction).hex()
tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash)
# print(tx_receipt)
assert(tx_receipt['status'] == 1)
selling_status = contract.functions.selling().call()
assert(selling_status == True)
print("[+] Done: changeSale")


print("[+] Start: changeCloudsPerEth")
tx = contract.functions.changeCloudsPerEth(800000).buildTransaction({
    "from": owner_account.address,
    "value": 0,
    'gasPrice': web3.toWei(gas_price, "gwei"),
    "gas": gas_limit,
    "nonce": web3.eth.getTransactionCount(owner_account.address),
})
signed_tx = owner_account.signTransaction(tx)
tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction).hex()
tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash)
# print(tx_receipt)
assert(tx_receipt['status'] == 1)
cloudsPerEth = contract.functions.cloudsPerEth().call()
assert(cloudsPerEth == 800000)
print("[+] Done: changeCloudsPerEth")

print("[+] Start: Check initial status")
owner_address = contract.functions.owner().call()
assert(owner_account.address == owner_address)
owner_token_balance = contract.functions.balanceOf(owner_account.address).call()
total_supply = contract.functions.totalSupply().call()
assert(owner_token_balance == total_supply)
user_token_balance = contract.functions.balanceOf(user_account.address).call()
assert(user_token_balance == 0)
contract_eth_balance = web3.eth.getBalance(contract_address)
assert(contract_eth_balance == 0)
user_eth_balance_bef = web3.eth.getBalance(user_account.address)
print("[+] Done: Check initial status")

print("[+] Start: sale")
tx = contract.functions.sale().buildTransaction({
    "from": user_account.address,
    "value": web3.toWei(0.0005, "ether"),
    'gasPrice': web3.toWei(gas_price, "gwei"),
    "gas": gas_limit,
    "nonce": web3.eth.getTransactionCount(user_account.address),
})
signed_tx = user_account.signTransaction(tx)
tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction).hex()
tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash)
assert(tx_receipt['status'] == 1)
print("[+] Done: sale")


print("[+] Start: Check now status")
owner_token_balance = contract.functions.balanceOf(owner_account.address).call()
assert(owner_token_balance == 1000000000000000)
user_token_balance = contract.functions.balanceOf(user_account.address).call()
assert(user_token_balance == 0)
contract_eth_balance = web3.eth.getBalance(contract_address)
assert(contract_eth_balance == web3.toWei(0.0005, "ether"))
user_eth_balance_now = web3.eth.getBalance(user_account.address)
assert(user_eth_balance_now <= user_eth_balance_bef - web3.toWei(0.0005, "ether"))
print("[+] Done: Check now status")
