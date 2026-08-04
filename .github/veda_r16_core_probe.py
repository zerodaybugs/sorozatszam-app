#!/usr/bin/env python3
"""Read-only current-state probe for published Veda core deployments.

Allowed JSON-RPC methods only: eth_chainId, eth_blockNumber,
eth_getBlockByNumber, eth_getCode, eth_call. No signer or write path exists.
"""
from __future__ import annotations

import json
import random
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

EOA = "0x000000000000000000000000000000000000dEaD"
ZERO = "0x" + "0" * 40
ALLOWED = {"eth_chainId", "eth_blockNumber", "eth_getBlockByNumber", "eth_getCode", "eth_call"}
FORBIDDEN = {"eth_sendTransaction", "eth_sendRawTransaction", "eth_signTransaction", "personal_sendTransaction", "eth_estimateGas"}
S = {
    "owner": "8da5cb5b", "authority": "bf7e214f", "vault": "fbfa77cf", "accountant": "4fb3ccc5",
    "hook": "7f5a7c7b", "totalSupply": "18160ddd", "balanceOf": "70a08231", "decimals": "313ce567",
    "shareLockPeriod": "9fdb11b6", "depositCap": "dbd5edc7", "isPaused": "b187bd26",
    "assetData": "41fee44a", "currentBufferHelpers": "c8285411", "accountantState": "433255de",
    "vestingState": "32a633c0", "supplyObservation": "05cc0ed8", "getRate": "679aefce",
    "getRateSafe": "282a8700", "lastVirtualSharePrice": "cff8ec79", "totalAssets": "01e1d114",
    "pendingVesting": "c830136a", "pendingUnvested": "f3e5b2d4", "minimumVestingTime": "ff21a779",
    "maximumVestingTime": "55da7cb7", "maxDeviationYield": "07586faf", "maxDeviationLoss": "2814ab6b",
    "lastStrategistUpdateTimestamp": "c436a2d4", "base": "5001f3b5", "ONE_SHARE": "b7d122b5",
    "getRequestIds": "ac33a273", "withdrawAssets": "aa5a0ffd", "excessToSolverNonSelfSolve": "6b9f9fef",
    "aaveV3Pool": "86a06ff0",
}
PRODUCTS = [
    {
        "id": "balanced-usdc-ink", "chain_id": 57073,
        "rpc": ["https://rpc-gel.inkonchain.com", "https://rpc-qnd.inkonchain.com", "https://ink.drpc.org"],
        "vault": "0xcaae49fb7f74cCFBE8A05E6104b01c097a78789f",
        "accountant": "0x0C4dF79d9e35E5C4876BC1aE4663E834312DDc67",
        "teller": "0xC151E263d5c890FD0Bceb33a6525F1A76a8329fC",
        "queue": "0x4c433Ed6d57316170565D7Fedc11a841832cDc3d",
        "solver": "0xFfDffb178Cb469002B77b47f7e4a6bCAd041a9b6",
        "authority": "0x3E8B0ee1D05267fE9F8d2b1f8CB48F2e23d69c6B",
        "buffer": "0xc11c44c8b44355c41d7E7f88f07e9EA5b9625Eb4",
        "usdc": "0x2D270e6886d130D724215A266106e6832161EAEd",
    },
    {
        "id": "boosted-usdc-ink", "chain_id": 57073,
        "rpc": ["https://rpc-gel.inkonchain.com", "https://rpc-qnd.inkonchain.com", "https://ink.drpc.org"],
        "vault": "0xDbD87325D7b1189Dcc9255c4926076fF4a96A271",
        "accountant": "0x9c2477D4Ea17d3cCC45e6b1087c94d14926F54C9",
        "teller": "0xc46f2443b3521632E2E2a903D6da8f965B46f6a0",
        "queue": "0x406E63323EF5d39D41C6fD895Ef9665AF926184c",
        "solver": "0xdf4123c18DC985ed94061f2C08cE17b7b17f21fF",
        "authority": "0x1F53135155d6fF516bCcfDd9424fcdB8AD1eFB77",
        "buffer": "0x1bAb9A7d8b56C2c67889466cc6dca6F5821f6dc7",
        "usdc": "0x2D270e6886d130D724215A266106e6832161EAEd",
    },
    {
        "id": "boosted-usdc-ethereum", "chain_id": 1,
        "rpc": ["https://ethereum-rpc.publicnode.com", "https://eth.llamarpc.com", "https://rpc.flashbots.net", "https://1rpc.io/eth"],
        "vault": "0xDbD87325D7b1189Dcc9255c4926076fF4a96A271",
        "accountant": "0x62A88Bea6fe527b5DEfAA103A3f8b5010205aF92",
        "teller": "0x4E0292caa97128e35a695dCd53c465E56F69c3A0",
        "queue": "0x359Db9A866c1276a571b3A9FbbBc47ED1F945E71",
        "solver": "0xde2519e53BE8DC8d87638e790DfCe20a74bc187e",
        "authority": "0x1F53135155d6fF516bCcfDd9424fcdB8AD1eFB77",
        "buffer": "0x1bAb9A7d8b56C2c67889466cc6dca6F5821f6dc7",
        "usdc": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    },
]


def addr(a: str) -> str:
    h = a.lower().removeprefix("0x")
    if len(h) != 40 or any(c not in "0123456789abcdef" for c in h): raise ValueError(a)
    return "0x" + h

def word_addr(a: str) -> str: return addr(a)[2:].rjust(64, "0")
def c0(name: str) -> str: return "0x" + S[name]
def ca(name: str, a: str) -> str: return "0x" + S[name] + word_addr(a)
def words(raw: str) -> list[int]:
    h = raw.removeprefix("0x")
    if len(h) % 64: raise ValueError("bad ABI length")
    return [int(h[i:i+64], 16) for i in range(0, len(h), 64)]
def u(raw: str) -> int: return int(raw, 16)
def b(raw: str) -> bool: return bool(u(raw))
def a(raw: str) -> str: return "0x" + raw.removeprefix("0x")[-40:].lower()
def dynamic_b32(raw: str) -> list[str]:
    h = raw.removeprefix("0x"); off = int(h[:64], 16) * 2; n = int(h[off:off+64], 16); start = off + 64
    if len(h) < start + 64*n: raise ValueError("truncated array")
    return ["0x" + h[start+64*i:start+64*(i+1)] for i in range(n)]
def asset_data(raw: str) -> dict[str, Any]:
    w=words(raw); return {"allowDeposits":bool(w[0]),"allowWithdraws":bool(w[1]),"sharePremiumBps":w[2]}
def buffers(raw: str) -> dict[str,str]:
    w=words(raw); return {"deposit":"0x"+f"{w[0]:064x}"[-40:],"withdraw":"0x"+f"{w[1]:064x}"[-40:]}
def vesting(raw: str) -> dict[str,int]:
    w=words(raw); return {"lastSharePrice":w[0],"vestingGains":w[1],"lastVestingUpdate":w[2],"startVestingTime":w[3],"endVestingTime":w[4]}
def supply_obs(raw: str) -> dict[str,int]:
    w=words(raw); return {"cumulativeSupply":w[0],"cumulativeSupplyLast":w[1],"lastUpdateTimestamp":w[2]}
def acct_state(raw: str) -> dict[str,Any]:
    w=words(raw); return {"payoutAddress":"0x"+f"{w[0]:064x}"[-40:],"highwaterMark":w[1],"feesOwedInBase":w[2],"totalSharesLastUpdate":w[3],"exchangeRate":w[4],"upper":w[5],"lower":w[6],"lastUpdateTimestamp":w[7],"isPaused":bool(w[8]),"minimumUpdateDelay":w[9],"platformFeeBps":w[10],"performanceFeeBps":w[11]}
def withdraw_asset(raw: str) -> dict[str,Any]:
    w=words(raw); return {"allowWithdraws":bool(w[0]),"secondsToMaturity":w[1],"minimumSecondsToDeadline":w[2],"minDiscountBps":w[3],"maxDiscountBps":w[4],"minimumShares":w[5],"withdrawCapacity":w[6]}
def error(e: Exception) -> str: return str(e).replace("\n"," ")[:1000]


class RPC:
    def __init__(self, chain_id: int, urls: list[str]):
        self.chain_id=chain_id; self.urls=urls; self.good=None; self.valid=set(); self.i=random.randint(1000,90000); self.block=None; self.hash=None
    def raw(self,url:str,method:str,params:list[Any])->Any:
        if method not in ALLOWED or method in FORBIDDEN: raise RuntimeError("blocked method "+method)
        self.i+=1; body=json.dumps({"jsonrpc":"2.0","id":self.i,"method":method,"params":params}).encode()
        req=urllib.request.Request(url,data=body,headers={"Content-Type":"application/json","User-Agent":"VedaR16ReadOnly/1.0"},method="POST")
        with urllib.request.urlopen(req,timeout=25) as r: result=json.loads(r.read().decode())
        if result.get("error"): raise RuntimeError(result["error"])
        return result.get("result")
    def request(self,method:str,params:list[Any])->Any:
        errors=[]; order=([self.good] if self.good else [])+[x for x in self.urls if x!=self.good]
        for _ in range(2):
            for url in order:
                try:
                    if url not in self.valid:
                        if int(self.raw(url,"eth_chainId",[]),16)!=self.chain_id: raise RuntimeError("wrong chain")
                        self.valid.add(url)
                    v=self.raw(url,method,params); self.good=url; return v
                except Exception as e: errors.append(urllib.parse.urlparse(url).netloc+":"+error(e))
            time.sleep(1)
        raise RuntimeError(" | ".join(errors[-8:]))
    def pin(self):
        self.block=self.request("eth_blockNumber",[]); z=self.request("eth_getBlockByNumber",[self.block,False]); self.hash=z["hash"]
    def code(self,target:str)->str: return self.request("eth_getCode",[addr(target),self.block])
    def call(self,target:str,data:str)->str: return self.request("eth_call",[{"from":EOA,"to":addr(target),"data":data},self.block])


def safe(fn:Callable[[],Any],decoder:Callable[[str],Any]=lambda x:x)->dict[str,Any]:
    try:
        raw=fn()
        if raw in (None,"0x","0x0"): return {"ok":False,"error":"empty return","raw":raw}
        return {"ok":True,"value":decoder(raw),"raw":raw}
    except Exception as e: return {"ok":False,"error":error(e)}
def val(x:Any,default=None): return x.get("value",default) if isinstance(x,dict) and x.get("ok") else default
def v0(r:RPC,target:str,name:str,decoder:Callable[[str],Any]=u): return safe(lambda:r.call(target,c0(name)),decoder)
def va(r:RPC,target:str,name:str,arg:str,decoder:Callable[[str],Any]=u): return safe(lambda:r.call(target,ca(name,arg)),decoder)
def code(r:RPC,target:str):
    x=safe(lambda:r.code(target)); raw=x.get("raw","") if x.get("ok") else ""
    return {**x,"hasCode":bool(x.get("ok") and raw not in ("0x","0x0")),"bytes":max(0,(len(raw)-2)//2) if raw else 0}


def inspect(p:dict[str,Any])->dict[str,Any]:
    out={"id":p["id"],"chainId":p["chain_id"],"addresses":{k:addr(p[k]) for k in ["vault","accountant","teller","queue","solver","authority","buffer","usdc"]}}
    r=RPC(p["chain_id"],p["rpc"])
    try: r.pin()
    except Exception as e: return {**out,"status":"RPC_PIN_FAILED","error":error(e)}
    out["block"]={"number":int(r.block,16),"numberHex":r.block,"hash":r.hash,"endpointHost":urllib.parse.urlparse(r.good or "").netloc}
    out["code"]={n:code(r,p[n]) for n in ["vault","accountant","teller","queue","solver","authority","buffer","usdc"]}
    out["teller"]={
        "vault":v0(r,p["teller"],"vault",a),"accountant":v0(r,p["teller"],"accountant",a),"authority":v0(r,p["teller"],"authority",a),
        "shareLockPeriod":v0(r,p["teller"],"shareLockPeriod"),"depositCap":v0(r,p["teller"],"depositCap"),"isPaused":v0(r,p["teller"],"isPaused",b),
        "assetDataUSDC":va(r,p["teller"],"assetData",p["usdc"],asset_data),"bufferHelpersUSDC":va(r,p["teller"],"currentBufferHelpers",p["usdc"],buffers),
    }
    out["accountant"]={
        "vault":v0(r,p["accountant"],"vault",a),"authority":v0(r,p["accountant"],"authority",a),"base":v0(r,p["accountant"],"base",a),"decimals":v0(r,p["accountant"],"decimals"),
        "accountantState":v0(r,p["accountant"],"accountantState",acct_state),"vestingState":v0(r,p["accountant"],"vestingState",vesting),"supplyObservation":v0(r,p["accountant"],"supplyObservation",supply_obs),
        "getRate":v0(r,p["accountant"],"getRate"),"getRateSafe":v0(r,p["accountant"],"getRateSafe"),"lastVirtualSharePrice":v0(r,p["accountant"],"lastVirtualSharePrice"),
        "totalAssets":v0(r,p["accountant"],"totalAssets"),"pendingVesting":v0(r,p["accountant"],"pendingVesting"),"pendingUnvested":v0(r,p["accountant"],"pendingUnvested"),
        "minimumVestingTime":v0(r,p["accountant"],"minimumVestingTime"),"maximumVestingTime":v0(r,p["accountant"],"maximumVestingTime"),
        "maxDeviationYield":v0(r,p["accountant"],"maxDeviationYield"),"maxDeviationLoss":v0(r,p["accountant"],"maxDeviationLoss"),"lastStrategistUpdateTimestamp":v0(r,p["accountant"],"lastStrategistUpdateTimestamp"),
    }
    out["vault"]={
        "authority":v0(r,p["vault"],"authority",a),"hook":v0(r,p["vault"],"hook",a),"decimals":v0(r,p["vault"],"decimals"),"totalSupply":v0(r,p["vault"],"totalSupply"),
        "usdcBalance":va(r,p["usdc"],"balanceOf",p["vault"]),"queueShareBalance":va(r,p["vault"],"balanceOf",p["queue"]),"solverShareBalance":va(r,p["vault"],"balanceOf",p["solver"]),
    }
    out["queue"]={
        "authority":v0(r,p["queue"],"authority",a),"accountant":v0(r,p["queue"],"accountant",a),"ONE_SHARE":v0(r,p["queue"],"ONE_SHARE"),"isPaused":v0(r,p["queue"],"isPaused",b),
        "requestIds":v0(r,p["queue"],"getRequestIds",dynamic_b32),"withdrawAssetUSDC":va(r,p["queue"],"withdrawAssets",p["usdc"],withdraw_asset),
    }
    out["solver"]={"authority":v0(r,p["solver"],"authority",a),"excessToSolverNonSelfSolve":v0(r,p["solver"],"excessToSolverNonSelfSolve",b)}
    out["buffer"]={"vault":v0(r,p["buffer"],"vault",a),"aaveV3Pool":v0(r,p["buffer"],"aaveV3Pool",a)}
    vest=val(out["accountant"]["vestingState"],{}); obs=val(out["accountant"]["supplyObservation"],{}); state=val(out["accountant"]["accountantState"],{})
    checks={
        "allCoreCode":all(out["code"][n].get("hasCode") for n in ["vault","accountant","teller","queue","solver","authority","usdc"]),
        "tellerVault":val(out["teller"]["vault"])==addr(p["vault"]),"tellerAccountant":val(out["teller"]["accountant"])==addr(p["accountant"]),
        "tellerAuthority":val(out["teller"]["authority"])==addr(p["authority"]),"accountantVault":val(out["accountant"]["vault"])==addr(p["vault"]),
        "accountantAuthority":val(out["accountant"]["authority"])==addr(p["authority"]),"queueAccountant":val(out["queue"]["accountant"])==addr(p["accountant"]),
        "queueAuthority":val(out["queue"]["authority"])==addr(p["authority"]),"solverAuthority":val(out["solver"]["authority"])==addr(p["authority"]),
        "vaultAuthority":val(out["vault"]["authority"])==addr(p["authority"]),"vaultHook":val(out["vault"]["hook"])==addr(p["teller"]),
        "accountantNotPaused":state.get("isPaused") is False,"tellerNotPaused":val(out["teller"]["isPaused"]) is False,"queueNotPaused":val(out["queue"]["isPaused"]) is False,
    }
    out["checks"]=checks
    out["analysis"]={
        "shareLockPeriodSeconds":val(out["teller"]["shareLockPeriod"]),"vestingGains":vest.get("vestingGains"),"vestingStart":vest.get("startVestingTime"),"vestingEnd":vest.get("endVestingTime"),
        "activeVestAtPinnedBlock":bool(vest and vest.get("vestingGains",0)>0 and int(r.request("eth_getBlockByNumber",[r.block,False])["timestamp"],16)<vest.get("endVestingTime",0)),
        "currentSupply":val(out["vault"]["totalSupply"]),"currentRate":val(out["accountant"]["getRate"]),"currentRequestCount":len(val(out["queue"]["requestIds"],[]) or []),
        "twapCumulativeDelta":obs.get("cumulativeSupply",0)-obs.get("cumulativeSupplyLast",0) if obs else None,"allBindingsPass":all(checks.values()),
    }
    out["status"]="COMPLETE"; return out


def main()->int:
    o=Path("veda-r16-output"); o.mkdir(exist_ok=True); rows=[]
    for p in PRODUCTS:
        print("[read-only]",p["id"],flush=True); rows.append(inspect(p))
    result={"schemaVersion":1,"generatedAtUnix":int(time.time()),"safety":{"readOnly":True,"allowedMethods":sorted(ALLOWED),"forbiddenMethods":sorted(FORBIDDEN),"transactionsConstructed":0,"transactionsSigned":0,"transactionsBroadcast":0},"products":rows}
    (o/"CORE_STATE.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    complete=[x for x in rows if x.get("status")=="COMPLETE"]
    md=["# Veda R16 core state","","| Product | Chain | Lock (s) | Active vest | Vesting gains | Supply | Requests | Bindings |","|---|---:|---:|---:|---:|---:|---:|---:|"]
    for x in rows:
        if x.get("status")!="COMPLETE": md.append(f"| {x['id']} | {x['chainId']} | — | — | — | — | — | {x.get('status')} |")
        else:
            z=x["analysis"]; md.append(f"| {x['id']} | {x['chainId']} | {z['shareLockPeriodSeconds']} | {z['activeVestAtPinnedBlock']} | {z['vestingGains']} | {z['currentSupply']} | {z['currentRequestCount']} | {z['allBindingsPass']} |")
    md += ["","No signing, broadcast, impersonation, or public-chain write occurred."]
    (o/"SUMMARY.md").write_text("\n".join(md)+"\n")
    print(f"[read-only] complete={len(complete)}/{len(rows)}",flush=True)
    return 0 if len(complete)==len(rows) else 2
if __name__=="__main__": sys.exit(main())
