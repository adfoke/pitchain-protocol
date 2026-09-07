#!/usr/bin/env python3
"""
Pitchain Existence Proof Protocol v1 —— 独立一致性验证器（纯 stdlib）

本文件只依据 protocol/SPEC.md 的文字定义实现，不 import 本仓库任何 TS 代码、
不读 @pitchain/core 的任何内部产物——这正是「第三方依规范独立实现」的自证样本。
（写它之前最后再看一眼规范，别偷看 TS 实现细节。）

用法:
    python3 pitchain_verify.py                # 跑 vectors 全量一致性
    python3 pitchain_verify.py --proof x.json --data <file> [--header-hex H] [--tx-hex T]
"""
from __future__ import annotations
import hashlib
import json
import sys
from pathlib import Path

V = Path(__file__).resolve().parent.parent / "vectors"


# ---------- 规范 §2-§3：哈希原语 ----------
def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def sha256d(b: bytes) -> bytes:
    return sha256(sha256(b))


def tag(s: str) -> bytes:
    return sha256(s.encode("utf-8"))


def hx(b: bytes) -> str:
    return b.hex()


def unh(s: str) -> bytes:
    return bytes.fromhex(s)


# ---------- 规范 §4：批次树 ----------
def leaf(data_hash: bytes) -> bytes:
    return sha256d(tag("pitchain/1/leaf") + data_hash)


def prev_leaf(prev_root: bytes) -> bytes:
    return sha256d(tag("pitchain/1/prev") + prev_root)


def node(a: bytes, b: bytes) -> bytes:
    return sha256d(tag("pitchain/1/node") + a + b)


def root_from_path(data_hash: str, index: int, leaf_count: int, path: list[str]) -> str:
    if leaf_count < 1 or not (0 <= index < leaf_count):
        raise ValueError("index/leafCount out of range")
    depth = (leaf_count - 1).bit_length()
    if len(path) != depth:
        raise ValueError(f"path depth {len(path)} != {depth}")
    cur = unh(hx(leaf(unh(data_hash))))
    pos = index
    for sib in path:
        cur = node(cur, unh(sib)) if pos % 2 == 0 else node(unh(sib), cur)
        pos //= 2
    return hx(cur)


# ---------- 规范 §5：锚定载荷 ----------
MAGIC = b"PCH1"
VERSION = 1
PAYLOAD_LEN = 45


def decode_payload(p: str) -> tuple[int, str]:
    b = unh(p)
    if len(b) != PAYLOAD_LEN:
        raise ValueError("payload length")
    if b[:4] != MAGIC:
        raise ValueError("magic")
    if b[4] != VERSION:
        raise ValueError("version")
    return int.from_bytes(b[5:13], "big"), hx(b[13:])


# ---------- 规范 §7.4：Bitcoin 区块包含（SPV） ----------
def btc_merkle_root(txid: str, branch: list[str], position: int) -> str:
    cur = unh(txid)[::-1]
    pos = position
    for sib in branch:
        s = unh(sib)[::-1]
        cur = sha256d(cur + s) if pos % 2 == 0 else sha256d(s + cur)
        pos //= 2
    return hx(cur[::-1])


def header_fields(header_hex: str) -> tuple[str, str]:
    b = unh(header_hex)
    if len(b) != 80:
        raise ValueError("header must be 80 bytes")
    return hx(b[36:68][::-1]), hx(sha256d(b)[::-1])  # (merkleRoot显示序, blockHash)


# ---------- 规范 §7.3：锚定交易脚本绑定 ----------
def op_return_payloads(tx_hex: str) -> list[str]:
    b = unh(tx_hex)
    i = 4
    segwit = b[i] == 0x00 and b[i + 1] == 0x01  # BIP144 marker+flag
    if segwit:
        i += 2  # 字段序：…vin ins vout outs witness locktime——outs 先于 witness
    vin = b[i]; i += 1
    for _ in range(vin):
        i += 36
        sl = b[i]; i += 1 + sl + 4
    # BIP144：witness 段在 outputs 之后——本函数读完 outputs 即止，无需跳段
    out: list[str] = []
    vout = b[i]; i += 1
    for _ in range(vout):
        i += 8
        sl = b[i]; i += 1
        script = b[i:i + sl]; i += sl
        if len(script) >= 2 and script[0] == 0x6A:
            j = 1
            while j < len(script):
                n = script[j]
                if 1 <= n <= 75:
                    out.append(hx(script[j + 1:j + 1 + n])); j += 1 + n
                elif n == 0x4C and j + 2 <= len(script):
                    l2 = script[j + 1]
                    out.append(hx(script[j + 2:j + 2 + l2])); j += 2 + l2
                else:
                    break
    return out


# ---------- 规范 §7：完整验证 ----------
def verify(proof: dict, data: bytes | None = None, header_hex: str | None = None,
           anchor_tx_hex: str | None = None) -> dict:
    ev, tree, anch = proof["evidence"], proof["tree"], proof["anchor"]
    # 1 data
    if data is not None and hx(sha256(data)) != ev["hash"]:
        return {"result": "INVALID", "class": "data"}
    # 2 tree
    if root_from_path(ev["hash"], proof["leaf"]["index"], tree["leafCount"], tree["path"]) != tree["root"]:
        return {"result": "INVALID", "class": "tree"}
    # 3 anchor payload consistency
    try:
        bid, root = decode_payload(anch["payload"])
    except Exception:
        return {"result": "INVALID", "class": "anchor"}
    if root != tree["root"] or int(proof["batch"]["id"]) != bid:
        return {"result": "INVALID", "class": "anchor"}
    # 3.5 script binding（有 tx 数据时必查，规范 §7.3）
    if anchor_tx_hex is not None and anch["payload"] not in op_return_payloads(anchor_tx_hex):
        return {"result": "INVALID", "class": "script"}
    # 4 inclusion（有区块头数据时必查）
    if header_hex is not None:
        if anch.get("blockHash") is None or anch.get("merkleBranch") is None or anch.get("position") is None:
            return {"result": "INVALID", "class": "inclusion"}
        hdr_root, blk_hash = header_fields(header_hex)
        if hdr_root != btc_merkle_root(anch["txid"], anch["merkleBranch"], anch["position"]):
            return {"result": "INVALID", "class": "inclusion"}
        if blk_hash != anch["blockHash"]:
            return {"result": "INVALID", "class": "inclusion"}
        if (anch.get("confirmationsAtIssue") or 0) < 6:
            return {"result": "PROVISIONAL", "class": None}
        return {"result": "VALID", "class": None, "timeUpperBound": anch.get("mtp"), "level": "spv"}
    return {"result": "VALID", "class": None, "level": "crypto"}


# ---------- 一致性运行：吃 vectors ----------
def level_for(expect: str) -> dict:
    return {"pass-crypto": {}, "pass-spv": {"header_hex": "ctx"}, "pass-full": {"header_hex": "ctx", "anchor_tx_hex": "ctx"}}[expect]


def run_vectors() -> int:
    fails, total = [], 0
    # tree 族
    for f in sorted((V / "tree").glob("n*.json")):
        t = json.loads(f.read_text())
        total += 1
        if hx(tag("pitchain/1/leaf")) != t["tagLeaf"] or hx(tag("pitchain/1/node")) != t["tagNode"]:
            fails.append(f"{t['id']}: tag mismatch"); continue
        for item in t["items"]:
            if leaf(unh(item["dataHash"])) != unh(item["leaf"]):
                fails.append(f"{t['id']}: leaf {item['src']}"); break
        for pr in t["proofs"]:
            got = root_from_path(t["items"][pr["index"]]["dataHash"], pr["index"], t["leafCount"], pr["path"])
            if got != pr["root"]:
                fails.append(f"{t['id']} proof[{pr['index']}] root {got} != {pr['root']}")
    # anchor 族
    a = json.loads((V / "anchor" / "payload.json").read_text())
    for c in a["cases"]:
        total += 1
        bid, root = decode_payload(c["payload"])
        if str(bid) != c["batchId"] or root != c["root"]:
            fails.append(f"anchor {c['batchId']}")
    # proof 族（正+负）
    for fam in ("positive", "negative"):
        doc = json.loads((V / "proof" / f"{fam}.json").read_text())
        for c in doc["cases"]:
            total += 1
            ctx = c.get("context", {})
            kwargs = {k: v for k, v in ctx.items() if k in ("headerHex", "anchorTxHex")}
            data = ctx["dataSrc"].encode("utf-8") if "dataSrc" in ctx else None
            res = verify(c["proof"], data=data,
                         header_hex=kwargs.get("headerHex"), anchor_tx_hex=kwargs.get("anchorTxHex"))
            want = c["expect"]
            ok = ((want.startswith("pass") and res["result"] == "VALID") or
                  (want == f"fail-{res['class']}"))
            if fam == "positive" and want == "pass-full" and res.get("level") != "spv":
                ok = False  # 必须真走到 header+script 全查
            if not ok:
                fails.append(f"{c['id']}: expect {want}, got {res}")
    for x in fails:
        print("✗", x)
    print(f"pitchain-conformance: {total - len(fails)}/{total} 组断言通过" if not fails else f"{len(fails)} 处失败")
    return 1 if fails else 0


def main() -> None:
    args = sys.argv[1:]
    if not args:
        sys.exit(run_vectors())
    proof = json.loads(Path(args[args.index("--proof") + 1]).read_text())
    data = None
    hh = th = None
    if "--data" in args:
        data = Path(args[args.index("--data") + 1]).read_bytes()
    if "--header-hex" in args:
        hh = args[args.index("--header-hex") + 1]
    if "--tx-hex" in args:
        th = args[args.index("--tx-hex") + 1]
    print(json.dumps(verify(proof, data, hh, th), ensure_ascii=False))


if __name__ == "__main__":
    main()
