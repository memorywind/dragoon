"""
Lv-1 Dragoon: vanilla passport-model RA (SIG + SIG), paper Fig. 1.

Attester and verifier each use the same Schnorr-style SIG (KBSDL unblinded path).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from ecdsa import ellipticcurve

from dragoon_lv3 import (
    KBSDL,
    KBSDLKeys,
    KBSDLSig,
    _curve_by_name,
    _point_bytes,
    serialize_kbs_sig,
)


@dataclass
class DragoonLv1Evidence:
    pka: ellipticcurve.Point
    m: bytes
    sigma_a: KBSDLSig


@dataclass
class DragoonLv1:
    curve_name: str
    kbs: KBSDL

    @staticmethod
    def create(curve_name: str) -> "DragoonLv1":
        return DragoonLv1(curve_name=curve_name, kbs=KBSDL(_curve_by_name(curve_name)))

    def att_kgen(self) -> KBSDLKeys:
        return self.kbs.kgen()

    def attest(self, ska: int, pka: ellipticcurve.Point, m: bytes) -> DragoonLv1Evidence:
        sigma_a = self.kbs.sign(ska, m)
        return DragoonLv1Evidence(pka=pka, m=m, sigma_a=sigma_a)

    def att_vf(self, ev: DragoonLv1Evidence) -> bool:
        return self.kbs.vf(ev.pka, ev.m, ev.sigma_a)

    def ver_kgen(self) -> KBSDLKeys:
        return self.kbs.kgen()

    def _final_message(self, ev: DragoonLv1Evidence) -> bytes:
        return _point_bytes(ev.pka) + ev.m + serialize_kbs_sig(self.kbs.curve, ev.sigma_a)

    def ver_sign(self, skv: int, ev: DragoonLv1Evidence) -> KBSDLSig | None:
        if not self.att_vf(ev):
            return None
        return self.kbs.sign(skv, self._final_message(ev))

    def fin_vf(self, pkv: ellipticcurve.Point, ev: DragoonLv1Evidence, sigma_fin: KBSDLSig) -> bool:
        if not self.att_vf(ev):
            return False
        return self.kbs.vf(pkv, self._final_message(ev), sigma_fin)


def run_full_protocol(dr: DragoonLv1, m: bytes) -> Tuple[DragoonLv1Evidence, KBSDLSig, KBSDLKeys]:
    att = dr.att_kgen()
    ev = dr.attest(att.sk, att.pk, m)
    ver = dr.ver_kgen()
    sigma_fin = dr.ver_sign(ver.sk, ev)
    assert sigma_fin is not None
    assert dr.fin_vf(ver.pk, ev, sigma_fin)
    return ev, sigma_fin, ver


def signature_byte_sizes(dr: DragoonLv1, ev: DragoonLv1Evidence, sigma_fin: KBSDLSig) -> dict:
    c = dr.kbs.curve
    sigma_a_bytes = len(serialize_kbs_sig(c, ev.sigma_a))
    sigma_fin_bytes = len(serialize_kbs_sig(c, sigma_fin))
    return {
        "sigma_attester_bytes": sigma_a_bytes,
        "sigma_final_bytes": sigma_fin_bytes,
        "sigma_total_bytes": sigma_a_bytes + sigma_fin_bytes,
        "attester_pk_bytes": len(_point_bytes(ev.pka)),
    }
