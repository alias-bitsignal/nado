from data_ops import get_byte_size
from transaction_ops import max_fee_transaction, sort_transaction_pool


def merge_buffer(from_buffer, to_buffer) -> dict: #fixme
    while get_byte_size(to_buffer) < 250000 and from_buffer:

        tx_key = max_fee_transaction(from_buffer)
        tx_value = from_buffer[tx_key]

        if tx_key not in to_buffer:
            to_buffer[tx_key] = tx_value
            from_buffer.pop(tx_key)

        from_buffer = sort_transaction_pool(from_buffer)
        to_buffer = sort_transaction_pool(to_buffer)

    return {"from_buffer": from_buffer,
            "to_buffer": to_buffer}
