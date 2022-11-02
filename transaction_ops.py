import glob
import json
import os
import time

import msgpack
import requests

from Curve25519 import sign, verify
from address import proof_sender
from address import validate_address
from block_ops import load_block
from config import get_config
from config import get_timestamp_seconds
from data_ops import sort_list_dict
from hashing import create_nonce, blake2b_hash
from keys import load_keys
from log_ops import get_logger
from account_ops import get_account, reflect_transaction


def calculate_fee():
    return 1

def get_recommneded_fee(target, port):
    url = f"http://{target}:{port}/get_recommended_fee"
    result = json.loads(requests.get(url, timeout=3).text)
    return result['fee']

def get_transaction(txid, logger):
    """return transaction based on txid"""
    transaction_path = f"transactions/{txid}.dat"
    if os.path.exists(transaction_path):
        with open(transaction_path, "r") as file:
            block_hash = json.load(file)
            block = load_block(block_hash=block_hash, logger=logger)

            for transaction in block["block_transactions"]:
                if transaction["txid"] == txid:
                    return transaction
    else:
        return None


def create_txid(transaction):
    return blake2b_hash(json.dumps(transaction))


def validate_uniqueness(transaction, logger):
    if get_transaction(transaction, logger=logger):
        return False
    else:
        return True


def incorporate_transaction(transaction, block_hash):
    reflect_transaction(transaction)
    index_transaction(transaction, block_hash=block_hash)


def validate_transaction(transaction, logger):
    accessible = list(dict.values(transaction))[0]
    txid = list(transaction.keys())[0]

    assert isinstance(transaction, dict), "Data structure incomplete"
    assert validate_origin(transaction), "Invalid origin"
    assert validate_address(accessible['sender']), f"Invalid sender {accessible['sender']}"
    assert validate_address(accessible["recipient"]), f"Invalid recipient {accessible['recipient']}"
    assert validate_uniqueness(txid, logger=logger), f"Transaction {txid} already exists"
    assert isinstance(accessible["fee"], int), "Transaction fee is not an integer"
    assert accessible["fee"] >= 0, "Transaction fee lower than zero"
    return True


def max_fee_transaction(transactions: dict) -> dict: #fixme
    """returns dictionary from dictionary of dictionaries with max value"""
    max_fee = -1
    max_fee_key = None
    for key, value in transactions.items():
        if value["fee"] > max_fee:
            max_fee = value["fee"]
            max_fee_key = key
    return max_fee_key

def sort_transaction_pool(transactions: dict) -> dict:
    """sorts dictionary of dictionaries based on a dictionary value"""
    return dict(sorted(transactions.items()))


def unindex_transaction(transaction):
    tx_path = f"transactions/{transaction['txid']}.dat"

    sender_address = transaction['sender']
    if tx_index_empty(sender_address):
        update_tx_index_folder(sender_address, get_tx_index_number(sender_address) - 1)
    index_number = get_tx_index_number(sender_address)

    sender_path = f"accounts/{transaction['sender']}/transactions/{index_number}/{transaction['txid']}.lin"
    while not os.path.exists(sender_path):
        index_number -= 1
        sender_path = f"accounts/{transaction['sender']}/transactions/{index_number}/{transaction['txid']}.lin"
        if index_number < 0:
            raise ValueError(f"Transaction {transaction['txid']} rollback index seeking below zero")

    recipient_address = transaction['sender']
    if tx_index_empty(recipient_address):
        update_tx_index_folder(recipient_address, get_tx_index_number(recipient_address) - 1)
    index_number = get_tx_index_number(recipient_address)

    recipient_path = f"accounts/{transaction['recipient']}/transactions/{index_number}/{transaction['txid']}.lin"

    if sender_path != recipient_path:
        while not os.path.exists(recipient_path):
            index_number -= 1
            recipient_path = f"accounts/{transaction['recipient']}/transactions/{index_number}/{transaction['txid']}.lin"
            if index_number < 0:
                raise ValueError(f"Transaction {transaction['txid']} rollback index seeking below zero")

    while True:
        try:
            os.remove(tx_path)
            os.remove(sender_path)
            if sender_path != recipient_path:
                os.remove(recipient_path)
        except Exception as e:
            raise ValueError(f"Failed to unindex transaction {transaction['txid']}: {e}")
        break


def get_transactions_of_account(account, logger, batch):
    if batch == "max":
        batch = get_tx_index_number(account)

    account_path = f"accounts/{account}/transactions/{batch}"
    transaction_files = glob.glob(f"{account_path}/*.lin")
    tx_list = []

    for transaction in transaction_files:
        no_ext_no_path = os.path.basename(os.path.splitext(transaction)[0])
        tx_data = get_transaction(no_ext_no_path, logger=logger)
        tx_list.append(tx_data)

    return {batch: tx_list}


def update_tx_index_folder(address, number):
    tx_index = f"accounts/{address}/index.dat"
    index = {"index_folder": number}
    with open(tx_index, "w") as outfile:
        json.dump(index, outfile)


def create_tx_indexer(address):
    tx_index = f"accounts/{address}/index.dat"
    if not os.path.exists(tx_index):
        index = {"index_folder": 0}
        with open(tx_index, "w") as outfile:
            json.dump(index, outfile)


def get_tx_index_number(address):
    tx_index = f"accounts/{address}/index.dat"
    with open(tx_index, "r") as infile:
        index_number = json.load(infile)["index_folder"]
    return index_number


def tx_index_empty(address):
    index_number = get_tx_index_number(address)
    transaction_files = glob.glob(f"accounts/{address}/transactions/{index_number}/*.lin")
    if len(transaction_files) == 0:
        os.rmdir(f"accounts/{address}/transactions/{index_number}")
        return True
    else:
        return False


def tx_index_full(address, full=500):
    index_number = get_tx_index_number(address)
    transaction_files = glob.glob(f"accounts/{address}/transactions/{index_number}/*.lin")
    if len(transaction_files) >= full:
        return True
    else:
        return False


def index_transaction(transaction, block_hash):
    tx_path = f"transactions/{transaction['txid']}.dat"
    with open(tx_path, "w") as tx_file:
        tx_file.write(json.dumps(block_hash))

    sender_address = transaction['sender']
    create_tx_indexer(sender_address)
    if tx_index_full(sender_address):
        update_tx_index_folder(sender_address, get_tx_index_number(sender_address) + 1)
    index_number = get_tx_index_number(sender_address)
    sender_path = f"accounts/{sender_address}/transactions/{index_number}"
    if not os.path.exists(sender_path):
        os.makedirs(sender_path)
    with open(f"{sender_path}/{transaction['txid']}.lin", "w") as tx_file:
        json.dump("", tx_file)

    recipient_address = transaction['recipient']
    if recipient_address != sender_address:
        create_tx_indexer(recipient_address)
        if tx_index_full(recipient_address):
            update_tx_index_folder(recipient_address, get_tx_index_number(recipient_address) + 1)
        index_number = get_tx_index_number(recipient_address)
        recipient_path = f"accounts/{recipient_address}/transactions/{index_number}"
        if not os.path.exists(recipient_path):
            os.makedirs(recipient_path)
        with open(f"{recipient_path}/{transaction['txid']}.lin", "w") as tx_file:
            json.dump("", tx_file)


def to_readable_amount(raw_amount: int) -> str:
    return f"{(raw_amount / 1000000000):.10f}"


def to_raw_amount(amount: [int, float]) -> int:
    return int(float(amount) * 1000000000)


def check_balance(account, amount, fee):
    """for single transaction, check if the fee and the amount spend are allowable"""
    balance = get_account(account)["account_balance"]
    assert (
            balance - amount - fee > 0 <= amount
    ), f"{account} spending more than owned in a single transaction"
    return True


def get_senders(transaction_pool: list) -> list:
    sender_pool = []
    for transaction in transaction_pool:
        if transaction["sender"] not in sender_pool:
            sender_pool.append(transaction["sender"])
    return sender_pool


def validate_single_spending(transaction_pool: dict, transaction):
    """validate spending of a single spender against his transactions in a transaction pool"""
    transaction_message = list(dict.values(transaction))[0]
    txid = list(transaction.keys())[0]

    transaction_pool[txid] = transaction_message

    sender = transaction_message["sender"]

    standing_balance = get_account(sender)["account_balance"]
    amount_sum = 0
    fee_sum = 0

    for key, value in transaction_pool.items():
        if value["sender"] == sender:
            check_balance(
                account=sender,
                amount=value["amount"],
                fee=value["fee"],
            )

            amount_sum += value["amount"]
            fee_sum += value["fee"]

            spending = amount_sum + fee_sum
            assert spending <= standing_balance, "Overspending attempt"
    return True


def validate_all_spending(transaction_pool: list):
    """validate spending of all spenders in a transaction pool against their transactions"""
    sender_pool = get_senders(transaction_pool)

    for sender in sender_pool:
        standing_balance = get_account(sender)["account_balance"]
        amount_sum = 0
        fee_sum = 0

        for tx in transaction_pool:
            if tx["sender"] == sender:
                check_balance(
                    account=sender,
                    amount=tx["amount"],
                    fee=tx["fee"],
                )

                amount_sum += tx["amount"]
                fee_sum += tx["fee"]

                spending = amount_sum + fee_sum
                assert spending <= standing_balance, "Overspending attempt"
    return True


def validate_origin(transaction: dict):
    """save signature and then remove it as it is not a part of the signed message"""
    transaction_accessible = list(dict.values(transaction))[0]

    signature = transaction_accessible["signature"]
    del transaction_accessible["signature"]

    assert proof_sender(
        sender=transaction_accessible["sender"], public_key=transaction_accessible["public_key"]
    ), "Invalid sender"

    assert verify(
        signed=signature,
        message=msgpack.packb(transaction),
        public_key=transaction_accessible["public_key"],
    ), "Invalid sender"

    return True


def create_transaction(sender, recipient, amount, public_key, private_key, timestamp, data, fee):
    """construct transaction, then add txid, then add signature as last"""
    transaction_message = {
        "sender": sender,
        "recipient": recipient,
        "amount": amount,
        "timestamp": timestamp,
        "data": data,
        "nonce": create_nonce(),
        "fee": fee,
        "public_key": public_key,
    }
    txid = create_txid(transaction_message)

    transaction = {txid: transaction_message}

    signature = sign(private_key=private_key, message=msgpack.packb(transaction))
    transaction[txid].update(signature=signature)

    return transaction


if __name__ == "__main__":
    logger = get_logger(file="transactions.log")

    print(
        get_transaction(
            "210777f644d43ff694f3d1b2f6412114bd53bf2db726388a1001440d214ff499",
            logger=logger,
        )
    )
    # print(get_account("noob23"))

    key_dict = load_keys()
    address = key_dict["address"]
    recipient = "ndo6a7a7a6d26040d8d53ce66343a47347c9b79e814c66e29"
    private_key = key_dict["private_key"]
    public_key = key_dict["public_key"]
    amount = to_raw_amount(0.1)
    data = {"data_id": "seek_id", "data_content": "some_actual_content"}

    config = get_config()
    ip = config["ip"]
    port = config["port"]

    create_tx_indexer(address)
    if tx_index_full(address):
        update_tx_index_folder(address, get_tx_index_number(address) + 1)
    get_tx_index_number(address)

    for x in range(0, 50000):
        try:
            transaction = create_transaction(
                sender=address,
                recipient=recipient,
                amount=amount,
                data=data,
                public_key=public_key,
                timestamp=get_timestamp_seconds(),
                fee=calculate_fee(),
                private_key=private_key
            )

            print(transaction)
            print(validate_transaction(transaction, logger=logger))

            requests.get(f"http://{ip}:{port}/submit_transaction?data={msgpack.packb(transaction)}", timeout=30)
        except Exception as e:
            print(e)

    # tx_pool = json.loads(requests.get(f"http://{ip}:{port}/transaction_pool").text, timeout=30)
