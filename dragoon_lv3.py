"""
Lv-3 Dragoon (DRAA): KBSDL + IBSDL per HeteroRA Dragoon paper (Fig. 3–5).

Additive EC notation: public keys are curve points; scalars mod curve order n.
"""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import Tuple

from ecdsa import curves, ellipticcurve
from ecdsa.curves import Curve


def _curve_by_name(name: str) -> Curve:
    m = {
        "SECP224R1": curves.NIST224p,
        "SECP256R1": curves.NIST256p,
        "SECP384R1": curves.NIST384p,
        "SECP521R1": curves.NIST521p,
    }
    if name not in m:
        raise ValueError(f"Unknown curve {name}")
    return m[name]


def _hash_name_for_curve(curve: Curve) -> str:
    bits = curve.baselen * 8  # baselen is byte length of field elements
    if bits <= 256:
        return "sha256"
    if bits <= 384:
        return "sha384"
    return "sha512"


def _zn_hash(data: bytes, order: int, hash_name: str) -> int:
    """Map {0,1}* to Z_order (paper H); reduction mod n."""
    h = hashlib.new(hash_name, data).digest()
    return int.from_bytes(h, "big") % order


def _point_bytes(P: ellipticcurve.Point) -> bytes:
    """Deterministic uncompressed encoding for hashing / IBS identity."""
    curve = P.curve()
    bl = curve.p().bit_length() // 8 + (1 if curve.p().bit_length() % 8 else 0)
    return b"\x04" + int(P.x()).to_bytes(bl, "big") + int(P.y()).to_bytes(bl, "big")


@dataclass
class KBSDLKeys:
    sk: int  # x
    pk: ellipticcurve.Point  # X = x*G


@dataclass
class KBSDLSig:
    R: ellipticcurve.Point
    s: int


class KBSDL:
    """Fig. 4 KBSDL over a fixed NIST curve."""

    def __init__(self, curve: Curve):
        self.curve = curve
        self.G = curve.generator
        self.n = curve.order
        self.p = curve.curve.p()
        self._hash = _hash_name_for_curve(curve)

    def kgen(self) -> KBSDLKeys:
        x = 1 + secrets.randbelow(self.n - 1)
        pk = x * self.G
        return KBSDLKeys(sk=x, pk=pk)

    def sign(self, sk: int, m: bytes) -> KBSDLSig:
        while True:
            r = 1 + secrets.randbelow(self.n - 1)
            R = r * self.G
            c = _zn_hash(_point_bytes(self.pk_from_sk(sk)) + _point_bytes(R) + m, self.n, self._hash)
            s = (r + c * sk) % self.n
            if s != 0:
                return KBSDLSig(R=R, s=s)

    def pk_from_sk(self, sk: int) -> ellipticcurve.Point:
        return sk * self.G

    def blgen(self) -> int:
        while True:
            beta = 1 + secrets.randbelow(self.n - 1)
            if pow(beta, self.n - 1, self.n) == 1:  # in Z_n^* for prime n
                return beta

    def blpubkey(self, pk: ellipticcurve.Point, bk: int) -> ellipticcurve.Point:
        return bk * pk

    def blsign(self, sk: int, bk: int, bpk: ellipticcurve.Point, m: bytes) -> KBSDLSig:
        while True:
            r = 1 + secrets.randbelow(self.n - 1)
            R = r * self.G
            c = _zn_hash(_point_bytes(bpk) + _point_bytes(R) + m, self.n, self._hash)
            beta_x = (bk * sk) % self.n
            s = (r + c * beta_x) % self.n
            if s != 0:
                return KBSDLSig(R=R, s=s)

    def vf(self, pk_hat: ellipticcurve.Point, m: bytes, sig: KBSDLSig) -> bool:
        c = _zn_hash(_point_bytes(pk_hat) + _point_bytes(sig.R) + m, self.n, self._hash)
        left = sig.s * self.G
        right = sig.R + c * pk_hat
        return left == right


@dataclass
class IBSDLMaster:
    msk_x: int
    mpk_X: ellipticcurve.Point
    curve: Curve
    G: ellipticcurve.Point
    n: int
    hash_name: str


@dataclass
class IBSDLUserSk:
    id_bytes: bytes
    R: ellipticcurve.Point
    s: int


@dataclass
class IBSDLSig:
    R: ellipticcurve.Point
    S: ellipticcurve.Point
    Y: ellipticcurve.Point
    z: int


class IBSDL:
    """Fig. 5 IBSDL (BNN-style) in ROM."""

    def __init__(self, curve: Curve):
        self.curve = curve
        self.G = curve.generator
        self.n = curve.order
        self._hash = _hash_name_for_curve(curve)

    def setup(self) -> IBSDLMaster:
        x = 1 + secrets.randbelow(self.n - 1)
        X = x * self.G
        return IBSDLMaster(msk_x=x, mpk_X=X, curve=self.curve, G=self.G, n=self.n, hash_name=self._hash)

    def extract(self, msk: IBSDLMaster, id_bytes: bytes) -> IBSDLUserSk:
        while True:
            r = 1 + secrets.randbelow(self.n - 1)
            R = r * self.G
            ce = _zn_hash(id_bytes + _point_bytes(R), msk.n, msk.hash_name)
            s = (r + ce * msk.msk_x) % msk.n
            if s != 0:
                return IBSDLUserSk(id_bytes=id_bytes, R=R, s=s)

    def sign(self, usk: IBSDLUserSk, m: bytes, mpk: IBSDLMaster) -> IBSDLSig:
        S = usk.s * mpk.G
        while True:
            y = 1 + secrets.randbelow(mpk.n - 1)
            Y = y * mpk.G
            c_sig = _zn_hash(
                usk.id_bytes + _point_bytes(usk.R) + _point_bytes(S) + _point_bytes(Y) + m,
                mpk.n,
                mpk.hash_name,
            )
            z = (y + c_sig * usk.s) % mpk.n
            if z != 0:
                return IBSDLSig(R=usk.R, S=S, Y=Y, z=z)

    def vf(self, mpk: IBSDLMaster, id_bytes: bytes, m: bytes, sig: IBSDLSig) -> bool:
        ce_p = _zn_hash(id_bytes + _point_bytes(sig.R), mpk.n, mpk.hash_name)
        c_sig_p = _zn_hash(
            id_bytes + _point_bytes(sig.R) + _point_bytes(sig.S) + _point_bytes(sig.Y) + m,
            mpk.n,
            mpk.hash_name,
        )
        if sig.S != sig.R + ce_p * mpk.mpk_X:
            return False
        left = sig.z * mpk.G
        right = sig.Y + c_sig_p * sig.S
        return left == right


def serialize_kbs_sig(curve: Curve, sig: KBSDLSig) -> bytes:
    return _point_bytes(sig.R) + int(sig.s).to_bytes((curve.order.bit_length() + 7) // 8, "big")


def serialize_ibs_sig(curve: Curve, sig: IBSDLSig) -> bytes:
    bl = (curve.order.bit_length() + 7) // 8
    return (
        _point_bytes(sig.R)
        + _point_bytes(sig.S)
        + _point_bytes(sig.Y)
        + int(sig.z).to_bytes(bl, "big")
    )


@dataclass
class DragoonLv3Evidence:
    bpk: ellipticcurve.Point
    m: bytes
    sigma_a: KBSDLSig


@dataclass
class DragoonLv3:
    curve_name: str
    kbs: KBSDL
    ibs: IBSDL

    @staticmethod
    def create(curve_name: str) -> "DragoonLv3":
        c = _curve_by_name(curve_name)
        return DragoonLv3(curve_name=curve_name, kbs=KBSDL(c), ibs=IBSDL(c))

    def att_kgen(self) -> KBSDLKeys:
        return self.kbs.kgen()

    def attest(self, ska: int, _pka: ellipticcurve.Point, m: bytes) -> Tuple[ellipticcurve.Point, KBSDLSig, int]:
        bk = self.kbs.blgen()
        bpk = self.kbs.blpubkey(_pka, bk)
        sigma_a = self.kbs.blsign(ska, bk, bpk, m)
        return bpk, sigma_a, bk

    def att_vf(self, bpk: ellipticcurve.Point, m: bytes, sigma_a: KBSDLSig) -> bool:
        return self.kbs.vf(bpk, m, sigma_a)

    def ver_kgen(self) -> IBSDLMaster:
        return self.ibs.setup()

    def prox_kgen(self, msk: IBSDLMaster, bpk: ellipticcurve.Point) -> IBSDLUserSk:
        id_bytes = _point_bytes(bpk)
        return self.ibs.extract(msk, id_bytes)

    def prox_sign(self, rk: IBSDLUserSk, ev: DragoonLv3Evidence, mpk: IBSDLMaster) -> IBSDLSig | None:
        if not self.att_vf(ev.bpk, ev.m, ev.sigma_a):
            return None
        msg = self._ibs_message(ev)
        return self.ibs.sign(rk, msg, mpk)

    def ver_sign(self, msk: IBSDLMaster, ev: DragoonLv3Evidence) -> IBSDLSig | None:
        if not self.att_vf(ev.bpk, ev.m, ev.sigma_a):
            return None
        rk = self.prox_kgen(msk, ev.bpk)
        msg = self._ibs_message(ev)
        return self.ibs.sign(rk, msg, msk)

    def fin_vf(self, mpk: IBSDLMaster, ev: DragoonLv3Evidence, sigma_fin: IBSDLSig) -> bool:
        if not self.att_vf(ev.bpk, ev.m, ev.sigma_a):
            return False
        msg = self._ibs_message(ev)
        return self.ibs.vf(mpk, _point_bytes(ev.bpk), msg, sigma_fin)

    def _ibs_message(self, ev: DragoonLv3Evidence) -> bytes:
        return _point_bytes(ev.bpk) + ev.m + serialize_kbs_sig(self.kbs.curve, ev.sigma_a)


def run_full_protocol(dr: DragoonLv3, m: bytes) -> Tuple[DragoonLv3Evidence, IBSDLSig, IBSDLMaster]:
    att = dr.att_kgen()
    bpk, sigma_a, _bk = dr.attest(att.sk, att.pk, m)
    ev = DragoonLv3Evidence(bpk=bpk, m=m, sigma_a=sigma_a)
    msk = dr.ver_kgen()
    sigma_fin = dr.ver_sign(msk, ev)
    assert sigma_fin is not None
    assert dr.fin_vf(msk, ev, sigma_fin)
    return ev, sigma_fin, msk


def signature_byte_sizes(dr: DragoonLv3, ev: DragoonLv3Evidence, sigma_fin: IBSDLSig) -> dict:
    c = dr.kbs.curve
    sigma_a_bytes = len(serialize_kbs_sig(c, ev.sigma_a))
    sigma_fin_bytes = len(serialize_ibs_sig(c, sigma_fin))
    return {
        "sigma_attester_bytes": sigma_a_bytes,
        "sigma_final_bytes": sigma_fin_bytes,
        "sigma_total_bytes": sigma_a_bytes + sigma_fin_bytes,
        "blinded_pk_bytes": len(_point_bytes(ev.bpk)),
    }
