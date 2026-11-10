"""Tamper-evident decision log (design, consideration 8 and Section 4.6).

Every record carries a sequence number, the hash of the previous record,
and its own hash: SHA-256 over the canonical JSON of the record without
its hash. Every `checkpoint_every` records, and on close, the log appends
a checkpoint to a separate file: an Ed25519 signature over the sequence
number and the head hash. A checkpoint fixes everything before it, so
edits, deletions, reordering, and truncation before the last checkpoint
are detected. Records hold metadata and content digests, never content.
"""
import base64
import datetime
import hashlib
import json
import os
import threading
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (Ed25519PrivateKey,
                                                               Ed25519PublicKey)

GENESIS = "sha256:" + "0" * 64


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(data):
    if isinstance(data, str):
        data = data.encode()
    return "sha256:" + hashlib.sha256(data).hexdigest()


def record_hash(rec):
    return digest(canonical({k: v for k, v in rec.items() if k != "hash"}))


def _message(seq, head):
    return f"bulkhead-log:{seq}:{head}".encode()


class Signer:
    """The log's Ed25519 key, kept where no partition can reach."""

    def __init__(self, key):
        self.key = key
        pub = key.public_key().public_bytes(serialization.Encoding.Raw,
                                            serialization.PublicFormat.Raw)
        self.key_id = "ed25519:" + hashlib.sha256(pub).hexdigest()[:16]

    @classmethod
    def load_or_create(cls, path):
        if os.path.exists(path):
            with open(path, "rb") as f:
                return cls(serialization.load_pem_private_key(f.read(), None))
        key = Ed25519PrivateKey.generate()
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
        signer = cls(key)
        with open(path + ".pub", "wb") as f:
            f.write(signer.public_pem())
        return signer

    def public_pem(self):
        return self.key.public_key().public_bytes(serialization.Encoding.PEM,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo)

    def sign(self, seq, head):
        return base64.b64encode(self.key.sign(_message(seq, head))).decode()


def _now_iso(t):
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ")


class DecisionLog:
    def __init__(self, path, signer=None, checkpoint_every=100, clock=time.time):
        self.path = path
        self.cp_path = path + ".checkpoints"
        self.signer = signer
        self.every = checkpoint_every
        self.clock = clock
        self.lock = threading.Lock()
        self.seq, self.head, self.cp_seq = 0, GENESIS, 0
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        if os.path.exists(path):                      # resume an existing chain
            with open(path) as f:
                for line in f:
                    if line.strip():
                        rec = json.loads(line)
                        self.seq, self.head = rec["seq"], rec["hash"]
        if os.path.exists(self.cp_path):
            with open(self.cp_path) as f:
                for line in f:
                    if line.strip():
                        self.cp_seq = json.loads(line)["seq"]

    def append(self, rec):
        """Add seq, ts, prev and hash to `rec`, write it, and return it."""
        with self.lock:
            t = self.clock()
            out = dict(rec, seq=self.seq + 1, ts=_now_iso(t), prev=self.head)
            out["hash"] = record_hash(out)
            with open(self.path, "a") as f:
                f.write(canonical(out) + "\n")
            self.seq, self.head = out["seq"], out["hash"]
            if self.signer and self.every and self.seq - self.cp_seq >= self.every:
                self._checkpoint()
        return out

    def _checkpoint(self):
        cp = {"seq": self.seq, "hash": self.head, "ts": _now_iso(self.clock()),
              "key": self.signer.key_id, "sig": self.signer.sign(self.seq, self.head)}
        with open(self.cp_path, "a") as f:
            f.write(canonical(cp) + "\n")
        self.cp_seq = self.seq
        return cp

    def checkpoint(self):
        with self.lock:
            if self.signer and self.seq > self.cp_seq:
                return self._checkpoint()
        return None

    def close(self):
        self.checkpoint()

    def offset(self):
        try:
            return os.path.getsize(self.path)
        except FileNotFoundError:
            return 0

    def records_since(self, offset=0):
        return read_records(self.path, offset)


def read_records(path, offset=0):
    try:
        with open(path) as f:
            f.seek(offset)
            return [json.loads(line) for line in f if line.strip()]
    except FileNotFoundError:
        return []


def verify(path, public_pem=None):
    """Check the chain and the checkpoints; returns a list of problems.

    With the public key, every checkpoint's signature is checked, and a
    tail after the last checkpoint is reported (it is not yet fixed).
    """
    problems, hashes = [], {}
    prev, expect = GENESIS, 1
    try:
        with open(path) as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        lines = []
    for n, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            problems.append(f"line {n}: not JSON")
            continue
        if rec.get("seq") != expect:
            problems.append(f"line {n}: seq {rec.get('seq')}, expected {expect}")
        if rec.get("prev") != prev:
            problems.append(f"line {n}: prev does not match the previous record's hash")
        if rec.get("hash") != record_hash(rec):
            problems.append(f"line {n}: hash does not match the record")
        hashes[rec.get("seq")] = rec.get("hash")
        prev, expect = rec.get("hash"), (rec.get("seq") or expect) + 1
    last = expect - 1
    key = serialization.load_pem_public_key(public_pem) if public_pem else None
    cp_last = 0
    try:
        with open(path + ".checkpoints") as f:
            cps = [json.loads(x) for x in f.read().splitlines() if x.strip()]
    except FileNotFoundError:
        cps = []
    for cp in cps:
        if hashes.get(cp["seq"]) != cp["hash"]:
            problems.append(f"checkpoint {cp['seq']}: the chain does not reach it "
                            f"(records changed or truncated)")
        if key is not None:
            try:
                if not isinstance(key, Ed25519PublicKey):
                    raise InvalidSignature()
                key.verify(base64.b64decode(cp["sig"]), _message(cp["seq"], cp["hash"]))
            except (InvalidSignature, ValueError):
                problems.append(f"checkpoint {cp['seq']}: bad signature")
        cp_last = max(cp_last, cp["seq"])
    if key is not None and last > cp_last:
        problems.append(f"records {cp_last + 1}-{last} are after the last checkpoint")
    return problems
