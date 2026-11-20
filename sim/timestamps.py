"""Timestamp scheme. T0 = latest validated ledger (lower bound), T1 = commitment(σe) anchored in a memo
(upper bound). Swap this module to change how capture time is proven; capture and verifier only call these."""

from datetime import datetime

from xrpl.clients import JsonRpcClient
from xrpl.models.requests import Ledger
from xrpl.wallet import Wallet

from sim.ledger import anchor_memo, latest_validated_ledger, lookup_tx
from sim.protocol import COMMITMENT_MEMO_TYPE, commitment
from sim.report import WARN, Check, check


def acquire_t0(client: JsonRpcClient) -> dict:
    return latest_validated_ledger(client)


def anchor_t1(client: JsonRpcClient, wallet: Wallet, sigma_e: str) -> dict:
    c = commitment(sigma_e)
    sent = anchor_memo(client, wallet, COMMITMENT_MEMO_TYPE, c)
    if not (sent["validated"] and sent["result"] == "tesSUCCESS"):
        raise RuntimeError(f"anchoring failed: {sent}")
    return {"commitment": c, "tx_hash": sent["hash"], "ledger_index": sent["ledger_index"],
            "close_time": sent["close_time"], "anchored_by": wallet.address}


def verify_window(client: JsonRpcClient, t0: dict, t1: dict | None, sigma_e: str) -> list[Check]:
    """Trusts only the ledger: the bundle's own T0/T1 claims are compared against what the chain says."""
    ledger = client.request(Ledger(ledger_index=t0["ledger_index"])).result.get("ledger", {})
    checks = [check("T0 ledger on-chain", ledger.get("ledger_hash") == t0["ledger_hash"],
                    f"ledger {t0['ledger_index']} closed {ledger.get('close_time_iso')}",
                    f"ledger {t0['ledger_index']} has a different hash or does not exist")]
    if t1 is None:
        checks.append(Check("T1 anchor", WARN, "offline capture: no upper bound on capture time"))
        return checks

    tx = lookup_tx(client, t1["tx_hash"])
    expected = commitment(sigma_e)
    anchored = (tx is not None and tx["validated"] and tx["result"] == "tesSUCCESS"
                and {"type": COMMITMENT_MEMO_TYPE, "data": expected} in tx["memos"])
    checks.append(check("T1 anchor = commitment(σe)", anchored,
                        f"tx validated in ledger {tx['ledger_index']}" if tx else "",
                        "anchor tx missing, not validated, or its memo is not commitment(σe)"))
    if not anchored:
        return checks

    checks.append(check("T1 claims match the chain",
                        t1["ledger_index"] == tx["ledger_index"] and t1["close_time"] == tx["close_time"],
                        detail_fail=f"bundle says ledger {t1['ledger_index']}, chain says {tx['ledger_index']}"))
    seconds = (datetime.fromisoformat(tx["close_time"]) - datetime.fromisoformat(ledger["close_time_iso"])).total_seconds()
    checks.append(check("T0 before T1", t0["ledger_index"] < tx["ledger_index"],
                        f"captured between {ledger['close_time_iso']} and {tx['close_time']} "
                        f"({seconds:.0f}s, {tx['ledger_index'] - t0['ledger_index']} ledgers)",
                        "T1 ledger is not after T0"))
    return checks
