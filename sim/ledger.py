from xrpl.clients import JsonRpcClient
from xrpl.models.requests import Ledger, ServerInfo, Tx
from xrpl.models.transactions import AccountSet, Memo
from xrpl.transaction import submit_and_wait
from xrpl.utils import hex_to_str, str_to_hex
from xrpl.wallet import Wallet

from sim.config import RPC_URL


def get_client() -> JsonRpcClient:
    return JsonRpcClient(RPC_URL)


def server_status(client: JsonRpcClient) -> dict:
    info = client.request(ServerInfo()).result["info"]
    ledger = info["validated_ledger"]
    return {
        "build": info["build_version"],
        "ledger_index": ledger["seq"],
        "ledger_age_s": ledger["age"],
        "reserve_base_xrp": ledger["reserve_base_xrp"],
        "reserve_inc_xrp": ledger["reserve_inc_xrp"],
    }


def latest_validated_ledger(client: JsonRpcClient) -> dict:
    ledger = client.request(Ledger(ledger_index="validated")).result["ledger"]
    return {
        "ledger_index": int(ledger["ledger_index"]),
        "ledger_hash": ledger["ledger_hash"],
        "close_time": ledger["close_time_iso"],
    }


def anchor_memo(client: JsonRpcClient, wallet: Wallet, memo_type: str, data: str) -> dict:
    tx = AccountSet(
        account=wallet.address,
        memos=[Memo(memo_type=str_to_hex(memo_type), memo_data=str_to_hex(data))],
    )
    return _summary(submit_and_wait(tx, client, wallet).result)


def lookup_tx(client: JsonRpcClient, tx_hash: str) -> dict:
    return _summary(client.request(Tx(transaction=tx_hash)).result)


def _summary(result: dict) -> dict:
    tx_json = result.get("tx_json", result)
    memos = [
        {
            "type": hex_to_str(m["Memo"].get("MemoType", "")),
            "data": hex_to_str(m["Memo"].get("MemoData", "")),
        }
        for m in tx_json.get("Memos", [])
    ]
    return {
        "hash": result["hash"],
        "validated": result.get("validated", False),
        "result": result["meta"]["TransactionResult"],
        "ledger_index": result.get("ledger_index"),
        "close_time": result.get("close_time_iso"),
        "memos": memos,
    }
