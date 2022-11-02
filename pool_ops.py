from data_ops import get_byte_size
from transaction_ops import max_fee_transaction, sort_transaction_pool


def merge_buffer(from_buffer, to_buffer) -> dict:
    while get_byte_size(to_buffer) < 250000 and from_buffer:
        tx_to_merge = max_fee_transaction(from_buffer)

        tx_key = list(dict.values(tx_to_merge))[0]
        tx_value = list(tx_to_merge.keys())[0]

        if tx_to_merge not in to_buffer:
            to_buffer[tx_key] = tx_value
            from_buffer.pop(tx_key)

        from_buffer = sort_transaction_pool(from_buffer)
        to_buffer = sort_transaction_pool(to_buffer)

    return {"from_buffer": from_buffer,
            "to_buffer": to_buffer}
