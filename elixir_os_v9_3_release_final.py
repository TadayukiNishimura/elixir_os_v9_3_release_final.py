# =====================================================================
# ELIXIR-OS v9.3: Publication Candidate & Verifiable Research Release
# Complete Production-Grade Reference Implementation with 10-Pillar Test Suite
# =====================================================================

"""
ELIXIR-OS v9.3 (Synchronized Research Reference Release): High-Assurance Control Kernel
---------------------------------------------------------------------------------------
This module provides a mathematically consistent research reference implementation
incorporating transactional state management (snapshots and rollback), persistent 
append-only tamper-evident audit chains with reboot recovery (os.fsync), independent 
cryptographically chained rejected-candidate forensic logging, strict Config validation, 
and dry-run atomic PLC/fieldbus batch validation.

Status and Scope:
- Simulation-only research reference implementation.
- Not a clinical device, validated biological model, or physical safety controller.
- The risk metric Tr(P)/R^2 is a covariance-derived uncertainty indicator for supervisory 
  mode switching and does not constitute a calibrated biological safety probability.
"""

from __future__ import annotations
import copy
import hashlib
import hmac
import json
import logging
import math
import os
import sys
import time
import unittest
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import scipy
from scipy.linalg import expm

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s.%(msecs)03d] [%(levelname)s] (ELIXIR-OS-v9.3): %(message)s',
    datefmt='%H:%M:%S'
)


class Status(str, Enum):
    """Operational states for ELIXIR-OS v9.3."""
    RUNNING = "RUNNING"
    SAFE_MODE = "SAFE_MODE"
    FAIL_CLOSED = "FAIL_CLOSED"


class ValidationError(ValueError):
    """Raised when configuration, input data, or matrix conditions fail validation."""
    pass


class SafetyError(RuntimeError):
    """Raised when safety limits are breached or state transitions fail."""
    pass


@dataclass(frozen=True)
class Config:
    """Rigorous configuration for ELIXIR-OS v9.3 system parameters with strict type guards."""
    dim_z: int = 15
    dim_d: int = 3
    dt_max: float = 1.0
    risk_epsilon: float = 0.05
    risk_radius: float = 2.0
    safe_lower: float = -5.0
    safe_upper: float = 5.0
    debt_critical: float = 1.0
    safe_enter: float = 0.05
    safe_recover: float = 0.04
    recover_samples: int = 3
    plc_timeout: float = 0.1
    plc_queue_max: int = 128

    def validate(self) -> None:
        int_fields = [
            ("dim_z", self.dim_z),
            ("dim_d", self.dim_d),
            ("recover_samples", self.recover_samples),
            ("plc_queue_max", self.plc_queue_max)
        ]
        for name, val in int_fields:
            if type(val) is not int or val < 1:
                raise ValidationError(f"Config field '{name}' must be a strict positive integer (got {type(val)}).")

        float_fields = [
            ("dt_max", self.dt_max),
            ("risk_epsilon", self.risk_epsilon),
            ("risk_radius", self.risk_radius),
            ("safe_lower", self.safe_lower),
            ("safe_upper", self.safe_upper),
            ("debt_critical", self.debt_critical),
            ("safe_enter", self.safe_enter),
            ("safe_recover", self.safe_recover),
            ("plc_timeout", self.plc_timeout)
        ]
        for name, val in float_fields:
            if type(val) is not float and type(val) is not int:
                raise ValidationError(f"Config field '{name}' must be numeric (got {type(val)}).")
            if not math.isfinite(float(val)):
                raise ValidationError(f"Config field '{name}' must be a finite number.")

        if not (0.0 < float(self.risk_epsilon) < 1.0):
            raise ValidationError("risk_epsilon must be strictly within (0.0, 1.0).")

        if not (self.safe_lower < self.safe_upper):
            raise ValidationError("safe_lower must be strictly less than safe_upper.")

        if not (0 < self.safe_recover <= self.safe_enter <= self.risk_epsilon):
            raise ValidationError("Safety thresholds must satisfy 0 < safe_recover <= safe_enter <= risk_epsilon.")


class AuditChain:
    """
    Append-only, tamper-evident HMAC-SHA256 cryptographic hash chain with explicit storage 
    synchronization (os.fsync), persistent reboot recovery verification, and an independent 
    cryptographically chained rejected-evidence log.
    
    Threat Model Note:
    Provides tamper-evident verification of retained records against modification or reordering.
    Detection of complete log tail truncation requires an externally anchored checkpoint or 
    independently retained chain head (outside the scope of single-node storage).
    """
    def __init__(self, key: bytes, path: Optional[Path | str] = None, rejected_path: Optional[Path | str] = None):
        if not isinstance(key, bytes) or len(key) < 16:
            raise ValidationError("Audit signing key must be bytes with length >= 16.")
        self.key: bytes = key
        self.path: Optional[Path] = Path(path) if path else None
        self.rejected_path: Optional[Path] = Path(rejected_path) if rejected_path else None
        self.records: List[Dict[str, Any]] = []
        self.head: str = "0" * 64

        # Independent rejected-evidence hash chain state
        self.rejected_records: List[Dict[str, Any]] = []
        self.rejected_head: str = "0" * 64

        if self.path and self.path.exists():
            self._recover_from_disk()
        if self.rejected_path and self.rejected_path.exists():
            self._recover_rejected_from_disk()

    @staticmethod
    def canonical(obj: Any) -> bytes:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")

    def _recover_from_disk(self) -> None:
        loaded_records: List[Dict[str, Any]] = []
        prev_hash = "0" * 64
        try:
            with self.path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    rec = json.loads(line)
                    body_bytes = self.canonical(rec["payload"])
                    mac = hmac.new(self.key, body_bytes, hashlib.sha256).hexdigest()
                    digest = hashlib.sha256(bytes.fromhex(prev_hash) + body_bytes + bytes.fromhex(mac)).hexdigest()

                    if (
                        rec["previous"] != prev_hash
                        or not hmac.compare_digest(mac, rec["hmac_sha256"])
                        or not hmac.compare_digest(digest, rec["hash"])
                    ):
                        raise ValueError("Persistent audit log corruption or chain break detected during reboot recovery.")

                    loaded_records.append(rec)
                    prev_hash = digest
            self.records = loaded_records
            self.head = prev_hash
        except Exception as e:
            raise IOError(f"Failed to recover audit chain from disk: {e}")

    def _recover_rejected_from_disk(self) -> None:
        loaded_records: List[Dict[str, Any]] = []
        prev_hash = "0" * 64
        try:
            with self.rejected_path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    rec = json.loads(line)
                    evidence_obj = {
                        "timestamp": float(rec["timestamp"]),
                        "previous_rejection_hash": prev_hash,
                        "payload": rec["payload"]
                    }
                    body_bytes = self.canonical(evidence_obj)
                    mac = hmac.new(self.key, body_bytes, hashlib.sha256).hexdigest()
                    digest = hashlib.sha256(bytes.fromhex(prev_hash) + body_bytes + bytes.fromhex(mac)).hexdigest()

                    if (
                        rec["previous"] != prev_hash
                        or not hmac.compare_digest(mac, rec["hmac_sha256"])
                        or not hmac.compare_digest(digest, rec["hash"])
                    ):
                        raise ValueError("Rejected evidence log corruption or chain break detected during recovery.")

                    loaded_records.append(rec)
                    prev_hash = digest
            self.rejected_records = loaded_records
            self.rejected_head = prev_hash
        except Exception as e:
            raise IOError(f"Failed to recover rejected evidence chain from disk: {e}")

    def append(self, payload: Dict[str, Any]) -> str:
        body_bytes = self.canonical(payload)
        mac = hmac.new(self.key, body_bytes, hashlib.sha256).hexdigest()
        digest = hashlib.sha256(bytes.fromhex(self.head) + body_bytes + bytes.fromhex(mac)).hexdigest()

        record = {
            "previous": self.head,
            "payload": payload,
            "hmac_sha256": mac,
            "hash": digest
        }

        if self.path:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                line = json.dumps(record, sort_keys=True) + "\n"
                with self.path.open("a", encoding="utf-8") as f:
                    f.write(line)
                    f.flush()
                    os.fsync(f.fileno())
            except Exception as e:
                raise IOError(f"Failed to persist audit record to storage: {e}")

        self.records.append(record)
        self.head = digest
        return digest

    def append_rejected_evidence(self, rejected_payload: Dict[str, Any], timestamp: float) -> str:
        """
        Appends a rejected candidate state record to an independent cryptographic hash chain 
        authenticating timestamp, rejection reason, candidate state vector, and previous rejection hash.
        """
        evidence_obj = {
            "timestamp": float(timestamp),
            "previous_rejection_hash": self.rejected_head,
            "payload": rejected_payload
        }
        body_bytes = self.canonical(evidence_obj)
        mac = hmac.new(self.key, body_bytes, hashlib.sha256).hexdigest()
        digest = hashlib.sha256(bytes.fromhex(self.rejected_head) + body_bytes + bytes.fromhex(mac)).hexdigest()

        rec = {
            "previous": self.rejected_head,
            "timestamp": float(timestamp),
            "payload": rejected_payload,
            "hmac_sha256": mac,
            "hash": digest
        }

        if self.rejected_path:
            try:
                self.rejected_path.parent.mkdir(parents=True, exist_ok=True)
                line = json.dumps(rec, sort_keys=True) + "\n"
                with self.rejected_path.open("a", encoding="utf-8") as f:
                    f.write(line)
                    f.flush()
                    os.fsync(f.fileno())
            except Exception as e:
                logging.error(f"Failed to write rejected forensic evidence: {e}")

        self.rejected_records.append(rec)
        self.rejected_head = digest
        return digest

    def verify(self) -> bool:
        prev_hash = "0" * 64
        try:
            for rec in self.records:
                body_bytes = self.canonical(rec["payload"])
                mac = hmac.new(self.key, body_bytes, hashlib.sha256).hexdigest()
                digest = hashlib.sha256(bytes.fromhex(prev_hash) + body_bytes + bytes.fromhex(mac)).hexdigest()

                if (
                    rec["previous"] != prev_hash
                    or not hmac.compare_digest(mac, rec["hmac_sha256"])
                    or not hmac.compare_digest(digest, rec["hash"])
                ):
                    return False
                prev_hash = digest
            return prev_hash == self.head
        except (KeyError, ValueError, TypeError):
            return False

    def verify_rejected(self) -> bool:
        prev_hash = "0" * 64
        try:
            for rec in self.rejected_records:
                evidence_obj = {
                    "timestamp": float(rec["timestamp"]),
                    "previous_rejection_hash": prev_hash,
                    "payload": rec["payload"]
                }
                body_bytes = self.canonical(evidence_obj)
                mac = hmac.new(self.key, body_bytes, hashlib.sha256).hexdigest()
                digest = hashlib.sha256(bytes.fromhex(prev_hash) + body_bytes + bytes.fromhex(mac)).hexdigest()

                if (
                    rec["previous"] != prev_hash
                    or not hmac.compare_digest(mac, rec["hmac_sha256"])
                    or not hmac.compare_digest(digest, rec["hash"])
                ):
                    return False
                prev_hash = digest
            return prev_hash == self.rejected_head
        except (KeyError, ValueError, TypeError):
            return False

    def snapshot(self) -> Tuple[List[Dict[str, Any]], str, List[Dict[str, Any]], str]:
        return copy.deepcopy(self.records), self.head, copy.deepcopy(self.rejected_records), self.rejected_head

    def restore(self, snapshot: Tuple[List[Dict[str, Any]], str, List[Dict[str, Any]], str]) -> None:
        recs, head_hash, rej_recs, rej_head = snapshot
        self.records = copy.deepcopy(recs)
        self.head = head_hash
        self.rejected_records = copy.deepcopy(rej_recs)
        self.rejected_head = rej_head


@dataclass
class PLCPacket:
    sequence: int
    timestamp: float
    fault: bool
    nonce: str
    mac: str


class PLCInbox:
    """
    Authenticated PLC / fieldbus heartbeat verification with dry-run atomic batch execution.
    All ingestion state variables S_PLC = (queue, seq, last_time, seen_nonces) are evaluated 
    against temporary copies. Live state is committed only after the complete batch passes; 
    otherwise, the entire batch is rejected and S_after == S_before holds strictly.
    """
    def __init__(self, key: bytes, timeout: float, max_queue: int):
        if not isinstance(key, bytes) or len(key) < 16:
            raise ValidationError("PLC HMAC secret key must be bytes with length >= 16.")
        self.key: bytes = key
        self.timeout: float = float(timeout)
        self.max_queue: int = int(max_queue)
        self.queue: List[PLCPacket] = []
        self.seq: int = -1
        self.last_time: Optional[float] = None
        self.seen_nonces: set[str] = set()

    @staticmethod
    def body(seq: int, ts: float, fault: bool, nonce: str) -> bytes:
        d = {"sequence": seq, "timestamp": ts, "fault": fault, "nonce": nonce}
        return json.dumps(d, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")

    def sign(self, seq: int, ts: float, fault: bool = False, nonce: str = "") -> PLCPacket:
        mac = hmac.new(self.key, self.body(seq, ts, fault, nonce), hashlib.sha256).hexdigest()
        return PLCPacket(sequence=seq, timestamp=ts, fault=fault, nonce=nonce, mac=mac)

    def ingest(self, packet: PLCPacket) -> None:
        if len(self.queue) >= self.max_queue:
            raise SafetyError("PLC packet buffer queue overflow.")
        self.queue.append(packet)

    def consume(self, now: Optional[float] = None) -> Tuple[bool, str]:
        now = time.monotonic() if now is None else float(now)
        if not math.isfinite(now):
            return False, "invalid_host_clock"

        if not self.queue:
            if self.last_time is not None and (now - self.last_time) <= self.timeout:
                return True, "heartbeat_ok"
            return (self.last_time is not None and (now - self.last_time) <= self.timeout), "heartbeat_timeout"

        # Temporary copies for dry-run validation
        temp_seq = self.seq
        temp_last_time = self.last_time
        temp_seen_nonces = set(self.seen_nonces)

        batch = list(self.queue)
        for p in batch:
            try:
                if (
                    not isinstance(p.sequence, int)
                    or not isinstance(p.timestamp, (int, float))
                    or not isinstance(p.fault, bool)
                    or not isinstance(p.nonce, str)
                    or not isinstance(p.mac, str)
                ):
                    return False, "malformed_packet"

                expected_mac = hmac.new(
                    self.key, self.body(p.sequence, p.timestamp, p.fault, p.nonce), hashlib.sha256
                ).hexdigest()
                if not hmac.compare_digest(expected_mac, p.mac):
                    return False, "authentication_failed"

                if p.nonce in temp_seen_nonces:
                    return False, "nonce_replay"
                temp_seen_nonces.add(p.nonce)

                expected_seq = 0 if temp_seq == -1 else temp_seq + 1
                if p.sequence != expected_seq:
                    return False, "sequence_gap_or_replay"

                age = now - p.timestamp
                if not math.isfinite(p.timestamp) or age < 0 or age > self.timeout:
                    return False, "stale_or_future_packet"
                if p.fault:
                    return False, "hardware_fault"

                temp_seq = p.sequence
                temp_last_time = now
            except (ValueError, TypeError, AttributeError):
                return False, "malformed_packet"

        # Atomic commit upon full batch validation success
        self.seq = temp_seq
        self.last_time = temp_last_time
        self.seen_nonces = temp_seen_nonces
        self.queue.clear()
        return True, "heartbeat_ok"

    def snapshot(self) -> Tuple[List[PLCPacket], int, Optional[float], set[str]]:
        return copy.deepcopy(self.queue), self.seq, self.last_time, copy.deepcopy(self.seen_nonces)

    def restore(self, snap: Tuple[List[PLCPacket], int, Optional[float], set[str]]) -> None:
        q, s, lt, sn = snap
        self.queue = copy.deepcopy(q)
        self.seq = s
        self.last_time = lt
        self.seen_nonces = copy.deepcopy(sn)


class ElixirOSv93:
    """
    ELIXIR-OS v9.3 Synchronized Research Reference Kernel Implementation.
    """
    def __init__(
        self,
        config: Config = Config(),
        seed: int = 42,
        audit_key: bytes = b"CHANGE_THIS_AUDIT_SECRET_32B",
        plc_key: bytes = b"CHANGE_THIS_PLC_SECRET_32B",
        audit_path: Optional[Path | str] = None,
        rejected_path: Optional[Path | str] = None
    ):
        config.validate()
        self.cfg: Config = config
        n, m = config.dim_z, config.dim_d

        self.rng: np.random.Generator = np.random.default_rng(seed)
        self.z: np.ndarray = np.zeros(n, dtype=np.float64)
        self.D: np.ndarray = np.zeros(m, dtype=np.float64)
        self.P: np.ndarray = 0.002 * np.eye(n, dtype=np.float64)

        self.Fc: np.ndarray = -0.1 * np.eye(n, dtype=np.float64)
        self.Gc: np.ndarray = 0.5 * np.ones((n, m), dtype=np.float64)
        self.Lc: np.ndarray = 0.05 * np.eye(n, dtype=np.float64)
        self.Qc: np.ndarray = self.Lc @ self.Lc.T

        self.status: Status = Status.RUNNING
        self.software_interlock_latched: bool = False
        self.fail_reason: Optional[str] = None
        self.nonce: int = 0
        self.recovery: int = 0

        self.audit: AuditChain = AuditChain(audit_key, audit_path, rejected_path)
        self.plc: PLCInbox = PLCInbox(plc_key, config.plc_timeout, config.plc_queue_max)

        self._validate_model()
        if not audit_path or not Path(audit_path).exists():
            self._audit("initialized")

    def _validate_model(self) -> None:
        n, m = self.cfg.dim_z, self.cfg.dim_d
        for name, arr, expected_shape in [("Fc", self.Fc, (n, n)), ("Gc", self.Gc, (n, m)), ("Qc", self.Qc, (n, n))]:
            a = np.asarray(arr)
            if a.shape != expected_shape or not np.all(np.isfinite(a)):
                raise ValidationError(f"Invalid shape or non-finite values in matrix {name}")

        if not np.allclose(self.Qc, self.Qc.T) or np.linalg.eigvalsh(self.Qc).min() < -1e-10:
            raise ValidationError("Process noise matrix Qc must be symmetric positive semi-definite (PSD).")

    @staticmethod
    def vector(x: Any, n: int, name: str) -> np.ndarray:
        a = np.asarray(x, dtype=np.float64)
        if a.shape != (n,) or not np.all(np.isfinite(a)):
            raise ValidationError(f"Vector {name} must be finite with shape ({n},)")
        return a

    def discretize(self, dt: float) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Discretizes continuous-time linear stochastic dynamics under ZOH input assumption 
        using Van Loan's block matrix exponential formulation.
        """
        if not math.isfinite(dt) or not (0 < dt <= self.cfg.dt_max):
            raise ValidationError(f"dt must be finite and within (0, {self.cfg.dt_max}]")

        n, m = self.cfg.dim_z, self.cfg.dim_d

        aug = np.zeros((n + m, n + m), dtype=np.float64)
        aug[:n, :n] = self.Fc
        aug[:n, n:] = self.Gc
        e_aug = expm(aug * dt)
        Ad = e_aug[:n, :n]
        Bd = e_aug[:n, n:]

        v = np.zeros((2 * n, 2 * n), dtype=np.float64)
        v[:n, :n] = self.Fc
        v[:n, n:] = self.Qc
        v[n:, n:] = -self.Fc.T
        ev = expm(v * dt)

        V2 = ev[:n, n:]
        Qd = V2 @ Ad.T
        Qd = (Qd + Qd.T) / 2.0

        if np.linalg.eigvalsh(Qd).min() < -1e-9:
            raise ArithmeticError("Discretized noise covariance matrix Qd is not PSD.")

        return Ad, Bd, Qd

    def risk(self) -> float:
        return float(np.trace(self.P) / (self.cfg.risk_radius ** 2))

    def state_safe(self, z_vec: Optional[np.ndarray] = None) -> bool:
        z_curr = self.z if z_vec is None else z_vec
        return bool(np.all(z_curr >= self.cfg.safe_lower) and np.all(z_curr <= self.cfg.safe_upper))

    def _audit(self, event: str, **extra: Any) -> None:
        payload = {
            "event": event,
            "nonce": self.nonce,
            "status": self.status.value,
            "z": self.z.tolist(),
            "D": self.D.tolist(),
            "P": self.P.tolist(),
            "software_interlock_latched": self.software_interlock_latched
        }
        payload.update(extra)
        self.audit.append(payload)

    def fail_closed(self, reason: str) -> None:
        self.status = Status.FAIL_CLOSED
        self.software_interlock_latched = True
        self.fail_reason = str(reason)
        self.recovery = 0
        self._audit("fail_closed", reason=self.fail_reason)

    def authorized_reset(self, external_approval_token: str) -> None:
        if not isinstance(external_approval_token, str) or len(external_approval_token) < 32:
            raise SafetyError("Authorized reset requires valid external security token (>=32 chars).")

        if (
            not self.software_interlock_latched
            or not self.state_safe()
            or self.risk() > self.cfg.safe_recover
            or np.max(self.D) >= self.cfg.debt_critical
        ):
            raise SafetyError("Reset preconditions not satisfied: System remains unsafe.")

        self.software_interlock_latched = False
        self.status = Status.SAFE_MODE
        self.fail_reason = None
        self.recovery = 0
        self._audit("authorized_reset")

    def check_plc(self, now: Optional[float] = None) -> bool:
        ok, reason = self.plc.consume(now)
        if not ok:
            self.fail_closed(reason)
        return ok

    def _snapshot(self) -> Tuple[Any, ...]:
        return copy.deepcopy((
            self.z,
            self.D,
            self.P,
            self.status,
            self.software_interlock_latched,
            self.fail_reason,
            self.nonce,
            self.recovery,
            self.rng.bit_generator.state,
            self.plc.snapshot(),
            self.audit.snapshot()
        ))

    def _restore(self, snapshot: Tuple[Any, ...]) -> None:
        (
            self.z, self.D, self.P, self.status, self.software_interlock_latched,
            self.fail_reason, self.nonce, self.recovery, rng_state, plc_snap, audit_snap
        ) = copy.deepcopy(snapshot)

        self.rng.bit_generator.state = rng_state
        self.plc.restore(plc_snap)
        self.audit.restore(audit_snap)

    def step(self, u: Any, dt: float) -> Dict[str, Any]:
        if self.status == Status.FAIL_CLOSED or self.software_interlock_latched:
            raise SafetyError("System locked in FAIL-CLOSED state. Authorized reset required.")

        u_vec = self.vector(u, self.cfg.dim_d, "u")
        snapshot = self._snapshot()

        try:
            Ad, Bd, Qd = self.discretize(float(dt))

            if self.status == Status.SAFE_MODE:
                u_vec = np.zeros(self.cfg.dim_d, dtype=np.float64)

            w_k = self.rng.multivariate_normal(np.zeros(self.cfg.dim_z), Qd)
            z_new = Ad @ self.z + Bd @ u_vec + w_k

            P_new = Ad @ self.P @ Ad.T + Qd
            P_new = (P_new + P_new.T) / 2.0

            if np.linalg.eigvalsh(P_new).min() < -1e-9:
                raise ArithmeticError("Updated covariance matrix P is not PSD.")

            alpha = np.resize([0.08, 0.06, 0.05], self.cfg.dim_d)
            beta = np.resize([0.15, 0.12, 0.10], self.cfg.dim_d)
            noise_d = self.rng.normal(0.0, 0.001 * math.sqrt(dt), self.cfg.dim_d)

            D_new = self.D + dt * (alpha * np.mean(np.abs(u_vec)) - beta * self.D) + noise_d
            D_new = np.maximum(0.0, D_new)

            if not all(np.all(np.isfinite(x)) for x in (z_new, P_new, D_new)):
                raise ArithmeticError("Non-finite state values generated during numerical update.")

            current_risk = float(np.trace(P_new) / (self.cfg.risk_radius ** 2))
            state_box_ok = bool(np.all(z_new >= self.cfg.safe_lower) and np.all(z_new <= self.cfg.safe_upper))
            max_debt_val = float(np.max(D_new))

            violation_reason = None
            if not state_box_ok:
                violation_reason = "state_safe_set_violation"
            elif max_debt_val >= self.cfg.debt_critical:
                violation_reason = "debt_threshold_exceeded"
            elif current_risk > self.cfg.risk_epsilon:
                violation_reason = "risk_epsilon_exceeded_fatal"

            if violation_reason:
                rejected_evidence = {
                    "reason": violation_reason,
                    "nonce_candidate": self.nonce + 1,
                    "z_candidate": z_new.tolist(),
                    "D_candidate": D_new.tolist(),
                    "P_trace": float(np.trace(P_new)),
                    "risk": current_risk
                }
                self.audit.append_rejected_evidence(rejected_evidence, timestamp=time.time())
                self.fail_closed(violation_reason)
                raise SafetyError(f"Step resulted in FAIL_CLOSED: {violation_reason}")

            self.z = z_new
            self.P = P_new
            self.D = D_new
            self.nonce += 1

            if current_risk > self.cfg.safe_enter:
                self.status = Status.SAFE_MODE
                self.recovery = 0
            elif self.status == Status.SAFE_MODE:
                if current_risk <= self.cfg.safe_recover:
                    self.recovery += 1
                    if self.recovery >= self.cfg.recover_samples:
                        self.status = Status.RUNNING
                        self.recovery = 0
                else:
                    self.recovery = 0

            self._audit("step", dt=float(dt), u=u_vec.tolist(), risk=current_risk)

            return self.metrics()

        except Exception as exc:
            if self.status != Status.FAIL_CLOSED:
                self._restore(snapshot)
                self.fail_closed(f"transaction_exception:{type(exc).__name__}:{exc}")
            raise

    def metrics(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "z_norm": float(np.linalg.norm(self.z)),
            "max_debt": float(np.max(self.D)),
            "uncertainty_bound": self.risk(),
            "state_safe": self.state_safe(),
            "nonce": self.nonce,
            "audit_head": self.audit.head
        }

    def avoidance_control(self, target: Any, gain: float = 0.1) -> np.ndarray:
        if self.status != Status.RUNNING or self.software_interlock_latched:
            return np.zeros(self.cfg.dim_d, dtype=np.float64)

        target_vec = self.vector(target, self.cfg.dim_z, "target")
        if not math.isfinite(gain) or gain < 0:
            raise ValidationError("Control gain must be finite and non-negative.")

        scalar = np.mean(target_vec - self.z) * gain
        return np.full(self.cfg.dim_d, np.clip(scalar, -0.1, 0.1), dtype=np.float64)


# =====================================================================
# Comprehensive 10-Case Automated Verification Test Suite
# =====================================================================

class TestsV93(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_audit = Path("test_audit_v93.jsonl")
        self.temp_rejected = Path("test_rejected_v93.jsonl")
        for p in [self.temp_audit, self.temp_rejected]:
            if p.exists():
                p.unlink()

    def tearDown(self) -> None:
        for p in [self.temp_audit, self.temp_rejected]:
            if p.exists():
                p.unlink()

    def test_audit_reboot_recovery(self) -> None:
        """Case 1: Persistent disk audit re-read & hash chain validation (including tamper detection)."""
        key = b"0123456789abcdef"
        k1 = ElixirOSv93(seed=42, audit_key=key, audit_path=self.temp_audit, rejected_path=self.temp_rejected)
        k1.step([0.01, 0.02, 0.03], 0.1)
        k1.step([0.01, 0.02, 0.03], 0.1)
        head_orig = k1.audit.head
        len_orig = len(k1.audit.records)

        k2 = ElixirOSv93(seed=42, audit_key=key, audit_path=self.temp_audit, rejected_path=self.temp_rejected)
        self.assertEqual(len(k2.audit.records), len_orig)
        self.assertEqual(k2.audit.head, head_orig)
        self.assertTrue(k2.audit.verify())

        # Corrupt disk log and confirm recovery rejects tampered log
        lines = self.temp_audit.read_text(encoding="utf-8").splitlines()
        corrupted = lines[0].replace("initialized", "tampered_event")
        self.temp_audit.write_text(corrupted + "\n" + "\n".join(lines[1:]) + "\n", encoding="utf-8")
        with self.assertRaises(IOError):
            ElixirOSv93(seed=42, audit_key=key, audit_path=self.temp_audit, rejected_path=self.temp_rejected)

    def test_rejected_evidence_preservation(self) -> None:
        """Case 2: Tamper-evident forensic capture of uncommitted states with independent HMAC chain."""
        key = b"0123456789abcdef"
        kernel = ElixirOSv93(seed=42, audit_key=key, audit_path=self.temp_audit, rejected_path=self.temp_rejected)
        kernel.z = np.full(kernel.cfg.dim_z, 10.0)
        with self.assertRaises(SafetyError):
            kernel.step([0.1, 0.1, 0.1], 0.1)

        self.assertTrue(self.temp_rejected.exists())
        self.assertTrue(kernel.audit.verify_rejected())
        with self.temp_rejected.open("r", encoding="utf-8") as f:
            rec = json.loads(f.readline())
            self.assertEqual(rec["payload"]["reason"], "state_safe_set_violation")
            self.assertIn("timestamp", rec)
            self.assertIn("hmac_sha256", rec)

    def test_plc_batch_rollback_and_malformed(self) -> None:
        """Case 3: Atomic batch rejection & full state preservation (S_after == S_before) on malformed packet."""
        plc = PLCInbox(b"0123456789abcdef", 1.0, 10)
        now = time.monotonic()
        p0 = plc.sign(0, now, nonce="n0")
        p1 = PLCPacket(sequence=1, timestamp=now, fault=False, nonce="n1", mac="invalid_mac")
        plc.ingest(p0)
        plc.ingest(p1)

        snap_before = plc.snapshot()
        ok, reason = plc.consume(now=now + 0.01)
        self.assertFalse(ok)
        self.assertEqual(reason, "authentication_failed")
        self.assertEqual(plc.seq, snap_before[1])
        self.assertEqual(plc.last_time, snap_before[2])
        self.assertEqual(plc.seen_nonces, snap_before[3])
        self.assertEqual(len(plc.queue), len(snap_before[0]))

    def test_covariance_psd_preservation(self) -> None:
        """Case 4: Long-term symmetry and PSD maintenance of covariance P."""
        kernel = ElixirOSv93(seed=123)
        for _ in range(10):
            kernel.step([0.05, -0.02, 0.01], 0.1)
            self.assertTrue(np.allclose(kernel.P, kernel.P.T))
            self.assertGreaterEqual(np.linalg.eigvalsh(kernel.P).min(), -1e-10)

    def test_config_type_and_range_validation(self) -> None:
        """Case 5: Strict type guards and threshold boundary enforcement."""
        with self.assertRaises(ValidationError):
            Config(dim_z=0).validate()
        with self.assertRaises(ValidationError):
            Config(risk_epsilon=1.5).validate()
        with self.assertRaises(ValidationError):
            Config(safe_upper=-10.0, safe_lower=10.0).validate()

    def test_fail_closed_latch_and_reset(self) -> None:
        """Case 6: Interlock latching and reset precondition checks."""
        kernel = ElixirOSv93(seed=42, audit_key=b"0123456789abcdef")
        kernel.fail_closed("test_manual_latch")
        self.assertEqual(kernel.status, Status.FAIL_CLOSED)
        with self.assertRaises(SafetyError):
            kernel.step([0.1, 0.1, 0.1], 0.1)

        with self.assertRaises(SafetyError):
            kernel.authorized_reset("short_token")

        valid_token = "A" * 32
        kernel.authorized_reset(valid_token)
        self.assertEqual(kernel.status, Status.SAFE_MODE)
        self.assertFalse(kernel.software_interlock_latched)

    def test_input_vector_and_matrix_sanitization(self) -> None:
        """Case 7: Vector dimension and finiteness validation."""
        kernel = ElixirOSv93(seed=42)
        with self.assertRaises(ValidationError):
            kernel.step([0.1, float("nan")], 0.1)
        with self.assertRaises(ValidationError):
            kernel.vector([1.0, 2.0], 3, "test_dim")

    def test_matrix_discretization_consistency(self) -> None:
        """Case 8: Matrix exponential accuracy and Qd PSD verification."""
        kernel = ElixirOSv93(seed=42)
        Ad, Bd, Qd = kernel.discretize(0.1)
        self.assertEqual(Ad.shape, (kernel.cfg.dim_z, kernel.cfg.dim_z))
        self.assertTrue(np.allclose(Qd, Qd.T))
        self.assertGreaterEqual(np.linalg.eigvalsh(Qd).min(), -1e-10)

    def test_operational_recovery_counter(self) -> None:
        """Case 9: Multi-sample recovery counter from SAFE_MODE to RUNNING."""
        kernel = ElixirOSv93(seed=42)
        kernel.status = Status.SAFE_MODE
        kernel.recovery = 0
        kernel.P = 0.0001 * np.eye(kernel.cfg.dim_z)
        kernel.step([0.0, 0.0, 0.0], 0.1)
        self.assertEqual(kernel.recovery, 1)

    def test_deterministic_reproducibility(self) -> None:
        """Case 10: Fixed seed deterministic reproducibility across instances."""
        k1 = ElixirOSv93(seed=999)
        k2 = ElixirOSv93(seed=999)
        m1 = k1.step([0.02, 0.01, -0.01], 0.1)
        m2 = k2.step([0.02, 0.01, -0.01], 0.1)
        self.assertEqual(m1["nonce"], m2["nonce"])
        self.assertTrue(np.allclose(k1.z, k2.z))


def print_environment_info() -> None:
    print(f"Python: {sys.version.split()[0]}")
    print(f"NumPy:  {np.__version__}")
    print(f"SciPy:  {scipy.__version__}")


if __name__ == "__main__":
    print_environment_info()
    unittest.main(argv=["__file__"], verbosity=2, exit=False)
