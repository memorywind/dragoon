"""
Lv-2 Dragoon: delegated RA (SIG + IBS), paper Fig. 2.

Attestation evidence uses unblinded SIG (KBSDL.Sign); verifier/proxy use IBSDL.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from ecdsa import ellipticcurve

from dragoon_lv3 import (
    IBSDL,
    IBSDLMaster,
    IBSDLSig,
    IBSDLUserSk,
    KBSDL,
    KBSDLKeys,
    KBSDLSig,
    _curve_by_name,
    _point_bytes,
    serialize_ibs_sig,
    serialize_kbs_sig,
)


@dataclass
class DragoonLv2Evidence:
    pka: ellipticcurve.Point
    m: bytes
    sigma_a: KBSDLSig


@dataclass
class DragoonLv2:
    curve_name: str
    kbs: KBSDL
    ibs: IBSDL

    @staticmethod
    def create(curve_name: str) -> "DragoonLv2":
        c = _curve_by_name(curve_name)
        return DragoonLv2(curve_name=curve_name, kbs=KBSDL(c), ibs=IBSDL(c))

    def att_kgen(self) -> KBSDLKeys:
        return self.kbs.kgen()

    def attest(self, ska: int, pka: ellipticcurve.Point, m: bytes) -> DragoonLv2Evidence:
        sigma_a = self.kbs.sign(ska, m)
        return DragoonLv2Evidence(pka=pka, m=m, sigma_a=sigma_a)

    def att_vf(self, ev: DragoonLv2Evidence) -> bool:
        return self.kbs.vf(ev.pka, ev.m, ev.sigma_a)

    def ver_kgen(self) -> IBSDLMaster:
        return self.ibs.setup()

    def prox_kgen(self, msk: IBSDLMaster, pka: ellipticcurve.Point) -> IBSDLUserSk:
        return self.ibs.extract(msk, _point_bytes(pka))

    def _ibs_message(self, ev: DragoonLv2Evidence) -> bytes:
        return _point_bytes(ev.pka) + ev.m + serialize_kbs_sig(self.kbs.curve, ev.sigma_a)

    def prox_sign(self, rk: IBSDLUserSk, ev: DragoonLv2Evidence, mpk: IBSDLMaster) -> IBSDLSig | None:
        if not self.att_vf(ev):
            return None
        return self.ibs.sign(rk, self._ibs_message(ev), mpk)

    def ver_sign(self, msk: IBSDLMaster, ev: DragoonLv2Evidence) -> IBSDLSig | None:
        if not self.att_vf(ev):
            return None
        rk = self.prox_kgen(msk, ev.pka)
        return self.ibs.sign(rk, self._ibs_message(ev), msk)

    def fin_vf(self, mpk: IBSDLMaster, ev: DragoonLv2Evidence, sigma_fin: IBSDLSig) -> bool:
        if not self.att_vf(ev):
            return False
        return self.ibs.vf(mpk, _point_bytes(ev.pka), self._ibs_message(ev), sigma_fin)


def run_full_protocol(dr: DragoonLv2, m: bytes) -> Tuple[DragoonLv2Evidence, IBSDLSig, IBSDLMaster]:
    att = dr.att_kgen()
    ev = dr.attest(att.sk, att.pk, m)
    msk = dr.ver_kgen()
    sigma_fin = dr.ver_sign(msk, ev)
    assert sigma_fin is not None
    assert dr.fin_vf(msk, ev, sigma_fin)
    return ev, sigma_fin, msk


def signature_byte_sizes(dr: DragoonLv2, ev: DragoonLv2Evidence, sigma_fin: IBSDLSig) -> dict:
    c = dr.kbs.curve
    sigma_a_bytes = len(serialize_kbs_sig(c, ev.sigma_a))
    sigma_fin_bytes = len(serialize_ibs_sig(c, sigma_fin))
    return {
        "sigma_attester_bytes": sigma_a_bytes,
        "sigma_final_bytes": sigma_fin_bytes,
        "sigma_total_bytes": sigma_a_bytes + sigma_fin_bytes,
        "attester_pk_bytes": len(_point_bytes(ev.pka)),
    }
