"""XRPL access: validated ledgers, transactions, ledger objects, account history, memos."""

from xrpl.clients import JsonRpcClient
from xrpl.models.requests import AccountTx, Ledger, LedgerEntry, Tx
from xrpl.models.transactions import Memo
from xrpl.models.transactions.transaction import Transaction
from xrpl.transaction import submit_and_wait
from xrpl.utils import str_to_hex
from xrpl.wallet import Wallet

from decima.core.config import RPC_URL


def get_client() -> JsonRpcClient:
    return JsonRpcClient(RPC_URL)


def _ledger(client: JsonRpcClient, **selector) -> dict | None:
    response = client.request(Ledger(**selector))
    if not response.is_successful() or not response.result.get("validated"):
        return None
    ledger = response.result["ledger"]
    return {"index": int(ledger["ledger_index"]), "hash": ledger["ledger_hash"],
            "close_time": ledger["close_time_iso"]}


def latest_validated_ledger(client: JsonRpcClient) -> dict:
    return _ledger(client, ledger_index="validated")


def ledger_by_hash(client: JsonRpcClient, ledger_hash: str) -> dict | None:
    """The validated ledger with this hash, or None if no validated ledger has it."""
    return _ledger(client, ledger_hash=ledger_hash)


def memo(memo_type: str, data: bytes) -> Memo:
    return Memo(memo_type=str_to_hex(memo_type), memo_data=data.hex())


def submit(client: JsonRpcClient, tx: Transaction, wallet: Wallet) -> dict:
    result = submit_and_wait(tx, client, wallet).result
    if result["meta"]["TransactionResult"] != "tesSUCCESS":
        raise RuntimeError(f"{tx.transaction_type} failed: {result['meta']['TransactionResult']}")
    return {"hash": result["hash"], "ledger_index": result["ledger_index"],
            "close_time": result.get("close_time_iso")}


def lookup_tx(client: JsonRpcClient, tx_hash: str) -> dict | None:
    response = client.request(Tx(transaction=tx_hash))
    return response.result if response.is_successful() and response.result.get("validated") else None


def ledger_entry(client: JsonRpcClient, **selector) -> dict | None:
    response = client.request(LedgerEntry(ledger_index="validated", **selector))
    return response.result["node"] if response.is_successful() else None


def account_history(client: JsonRpcClient, address: str) -> list[dict]:
    """Validated, successful transactions of an account, oldest first, as {tx, meta, hash, ledger_index}."""
    txs, marker = [], None
    while True:
        result = client.request(AccountTx(account=address, forward=True, marker=marker)).result
        for t in result["transactions"]:
            if t.get("validated") and t["meta"]["TransactionResult"] == "tesSUCCESS":
                txs.append({"tx": t.get("tx_json", t.get("tx", {})), "meta": t["meta"],
                            "hash": t.get("hash") or t.get("tx_json", {}).get("hash"),
                            "ledger_index": t.get("ledger_index") or t.get("tx_json", {}).get("ledger_index")})
        marker = result.get("marker")
        if not marker:
            return txs


def memos(tx_json: dict) -> list[tuple[str, bytes]]:
    out = []
    for m in tx_json.get("Memos", []):
        try:
            memo_type = bytes.fromhex(m["Memo"].get("MemoType", "")).decode()
        except UnicodeDecodeError:
            continue
        out.append((memo_type, bytes.fromhex(m["Memo"].get("MemoData", ""))))
    return out
