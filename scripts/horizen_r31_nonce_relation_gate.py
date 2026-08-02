from __future__ import annotations

import json
import time
import urllib.parse
import urllib.request
from collections import defaultdict
from pathlib import Path

from coincurve import PublicKey

DEPLOYER = "0x9b264b21ca7659c256ad09171f827976acd5a1c3"
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
G = PublicKey(bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"))
CHAINS = {
    "mainnet": {
        "rpc": "https://horizen.calderachain.xyz/http",
        "explorer": "https://explorer.horizen.io",
    },
    "testnet": {
        "rpc": "https://horizen-testnet.rpc.caldera.xyz/http",
        "explorer": "https://explorer-testnet.horizen.io",
    },
}
REQUEST_ID = 0


def get_json(url: str, tries: int = 4):
    last = None
    for attempt in range(tries):
        try:
            request = urllib.request.Request(
                url,
                headers={
                    "accept": "application/json",
                    "user-agent": "Horizen-R31-readonly-nonce-gate/1",
                },
            )
            with urllib.request.urlopen(request, timeout=45) as response:
                return json.loads(response.read())
        except Exception as exc:
            last = exc
            time.sleep(2**attempt)
    raise RuntimeError(f"GET failed: {url}: {last}")


def rpc(url: str, method: str, params: list, tries: int = 4):
    global REQUEST_ID
    last = None
    for attempt in range(tries):
        REQUEST_ID += 1
        body = json.dumps(
            {"jsonrpc": "2.0", "id": REQUEST_ID, "method": method, "params": params}
        ).encode()
        request = urllib.request.Request(
            url,
            data=body,
            headers={
                "content-type": "application/json",
                "user-agent": "Horizen-R31-readonly-nonce-gate/1",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=45) as response:
                result = json.loads(response.read())
            if "error" in result:
                raise RuntimeError(result["error"])
            return result["result"]
        except Exception as exc:
            last = exc
            time.sleep(2**attempt)
    raise RuntimeError(f"RPC failed: {method}: {last}")


def collect_hashes(base: str) -> tuple[list[str], int]:
    url = f"{base}/api/v2/addresses/{DEPLOYER}/transactions"
    hashes: set[str] = set()
    pages = 0
    while url:
        obj = get_json(url)
        pages += 1
        for item in obj.get("items") or []:
            tx_hash = (item.get("hash") or "").lower()
            if tx_hash.startswith("0x"):
                hashes.add(tx_hash)
        next_page = obj.get("next_page_params")
        url = (
            f"{base}/api/v2/addresses/{DEPLOYER}/transactions?"
            + urllib.parse.urlencode(next_page)
            if next_page
            else None
        )
    return sorted(hashes), pages


def integer(value: str | None) -> int:
    return int(value or "0x0", 16)


def parity(tx: dict) -> int:
    tx_type = integer(tx.get("type"))
    v = integer(tx.get("v"))
    if tx_type in (1, 2, 3, 4):
        return v & 1
    if v in (27, 28):
        return v - 27
    return (v - 35) & 1


def negate(point: PublicKey) -> PublicKey:
    compressed = point.format(compressed=True)
    return PublicKey(bytes([compressed[0] ^ 1]) + compressed[1:])


def r_candidates(r: int, y_parity: int) -> list[PublicKey]:
    candidates: list[PublicKey] = []
    for x_coordinate in (r, r + N):
        if x_coordinate >= P:
            continue
        try:
            candidates.append(
                PublicKey(bytes([2 + y_parity]) + x_coordinate.to_bytes(32, "big"))
            )
        except Exception:
            pass
    if not candidates:
        raise AssertionError("valid signature produced no R-point candidate")
    return candidates


def main() -> int:
    rows: list[dict] = []
    coverage: dict[str, dict] = {}
    for label, config in CHAINS.items():
        hashes, pages = collect_hashes(config["explorer"])
        transactions = []
        for tx_hash in hashes:
            tx = rpc(config["rpc"], "eth_getTransactionByHash", [tx_hash])
            if tx and (tx.get("from") or "").lower() == DEPLOYER:
                transactions.append(tx)
        transactions.sort(key=lambda item: integer(item["nonce"]))
        latest_nonce = integer(
            rpc(config["rpc"], "eth_getTransactionCount", [DEPLOYER, "latest"])
        )
        observed_nonces = [integer(item["nonce"]) for item in transactions]
        if observed_nonces != list(range(latest_nonce)):
            raise AssertionError(f"{label}: incomplete nonce coverage")
        for tx in transactions:
            r_value = integer(tx["r"])
            rows.append(
                {
                    "chain": label,
                    "hash": tx["hash"].lower(),
                    "nonce": integer(tx["nonce"]),
                    "r": r_value,
                    "points": r_candidates(r_value, parity(tx)),
                }
            )
        coverage[label] = {
            "transactions": len(transactions),
            "latest_nonce": latest_nonce,
            "pages": pages,
            "full_nonce_coverage": True,
        }

    by_r: dict[int, list[str]] = defaultdict(list)
    for row in rows:
        by_r[row["r"]].append(row["hash"])
    repeated_r = {str(r): hashes for r, hashes in by_r.items() if len(hashes) > 1}

    # Search every effective nonce k in [1, 2^32) using BSGS.
    baby_size = 1 << 16
    baby_steps: dict[bytes, int] = {}
    point = G
    for value in range(1, baby_size + 1):
        baby_steps.setdefault(point.format(compressed=True), value)
        point = PublicKey.combine_keys([point, G])
    giant_step = G.multiply(baby_size.to_bytes(32, "big"))
    negative_giant_step = negate(giant_step)
    small_nonce_hits: list[dict] = []
    for row in rows:
        for candidate_index, candidate in enumerate(row["points"]):
            gamma = candidate
            for giant_index in range(baby_size):
                baby_index = baby_steps.get(gamma.format(compressed=True))
                if baby_index is not None:
                    nonce_value = giant_index * baby_size + baby_index
                    if 0 < nonce_value < (1 << 32):
                        small_nonce_hits.append(
                            {
                                "hash": row["hash"],
                                "candidate_index": candidate_index,
                                "nonce_value": nonce_value,
                            }
                        )
                    break
                try:
                    gamma = PublicKey.combine_keys([gamma, negative_giant_step])
                except Exception:
                    break

    # Search k_j = +/- k_i + delta for |delta| <= 2^18.
    relation_bound = 1 << 18
    delta_points: dict[bytes, int] = {}
    point = G
    for delta in range(1, relation_bound + 1):
        delta_points.setdefault(point.format(compressed=True), delta)
        point = PublicKey.combine_keys([point, G])

    relation_hits: list[dict] = []
    for first_index, first in enumerate(rows):
        for second in rows[first_index + 1 :]:
            for first_candidate_index, first_point in enumerate(first["points"]):
                for second_candidate_index, second_point in enumerate(second["points"]):
                    relations: list[tuple[str, PublicKey]] = []
                    try:
                        relations.append(
                            (
                                "difference",
                                PublicKey.combine_keys([second_point, negate(first_point)]),
                            )
                        )
                    except Exception:
                        pass
                    try:
                        relations.append(
                            ("sum", PublicKey.combine_keys([second_point, first_point]))
                        )
                    except Exception:
                        pass
                    for mode, relation_point in relations:
                        delta = delta_points.get(relation_point.format(compressed=True))
                        sign = 1
                        if delta is None:
                            delta = delta_points.get(
                                negate(relation_point).format(compressed=True)
                            )
                            sign = -1
                        if delta is not None:
                            relation_hits.append(
                                {
                                    "first_hash": first["hash"],
                                    "second_hash": second["hash"],
                                    "first_candidate_index": first_candidate_index,
                                    "second_candidate_index": second_candidate_index,
                                    "mode": mode,
                                    "signed_delta": sign * delta,
                                }
                            )

    result = {
        "classification": "PUBLIC_READ_ONLY_NONCE_RELATION_GATE",
        "public_network_writes": 0,
        "collected_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "deployer": DEPLOYER,
        "coverage": coverage,
        "total_signatures": len(rows),
        "repeated_r_groups": repeated_r,
        "small_nonce_search_bound_exclusive": 1 << 32,
        "small_nonce_hits": small_nonce_hits,
        "additive_relation_bound": relation_bound,
        "relation_hits": relation_hits,
        "gates": {
            "full_nonce_coverage": all(
                value["full_nonce_coverage"] for value in coverage.values()
            ),
            "no_repeated_r": not repeated_r,
            "no_effective_nonce_below_2_32": not small_nonce_hits,
            "no_small_additive_nonce_relation": not relation_hits,
        },
    }

    output = Path("evidence/horizen-r31-nonce-relation-gate.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print("HORIZEN_R31_NONCE_JSON_BEGIN")
    print(json.dumps(result, indent=2, sort_keys=True))
    print("HORIZEN_R31_NONCE_JSON_END")
    if not all(result["gates"].values()):
        raise AssertionError("nonce relation gate found a candidate")
    print("HORIZEN_R31_NONCE_GATE=PASS")
    print("PUBLIC_NETWORK_WRITES=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
