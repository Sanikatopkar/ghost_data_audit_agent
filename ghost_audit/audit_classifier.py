"""Deterministic deletion-intent classification."""
from __future__ import annotations
import re
from .normalization import norm


class AuditClassifier:
    DELETE_PATTERNS = [
        r"\b(delet\w*|deletion|erase\w*|erasure|wipe|purge|destroy|remov\w*|removal|clos\w*|terminate\w*|forget)\b.{0,180}\b(account|profile|personal data|personal information|my data|my account|this account|records|details|traces|search result|export|archive|integration|copy|copies)\b",
        r"\b(account|profile|personal data|personal information|my data|my account|this account|records|details|traces|search result|export|archive|integration|copy|copies)\b.{0,180}\b(delet\w*|deletion|erase\w*|erasure|wipe|purge|destroy|remov\w*|removal|clos\w*|terminate\w*|forget|gone|removed|deleted|erased)\b",
        r"\b(account|profile|request)\b.{0,100}\b(gone|deleted|removed|erased|closed|failed|complete|completed)\b",
        r"\b(verify|check|confirm|audit|inspect|investigate)\b.{0,120}\b(deletion|suppression|deleted|removed|erased|gone|account|profile)\b",
        r"\b(suppression|effacement)\b.{0,100}\b(compte|donnees|profil)\b",
        r"\b(para borrar|eliminar|borrar|suprimir)\b.{0,100}\b(cuenta|datos|perfil)\b",
        r"\b(cuenta|datos personales|perfil)\b.{0,100}\b(eliminar|borrar|suprimir)\b",
        r"\b(supprimer|effacer|resilier)\b.{0,100}\b(compte|donnees|profil)\b",
        r"\b(compte|donnees personnelles|profil)\b.{0,100}\b(supprimer|effacer)\b",
        r"\b(konto|profil|daten)\b.{0,100}\b(loschen|entfernen)\b",
        r"\b(loschen|entfernen)\b.{0,100}\b(konto|profil|daten)\b",
        r"\b(cancellare|eliminare)\b.{0,100}\b(account|profilo|dati)\b",
        r"\b(account|profilo|dati personali)\b.{0,100}\b(cancellare|eliminare)\b",
        r"\b(excluir|apagar|eliminar)\b.{0,100}\b(conta|dados|perfil)\b",
        r"\b(conta|dados pessoais|perfil)\b.{0,100}\b(excluir|apagar|eliminar)\b",
        r"删除.{0,20}(账户|帳戶|账号|个人数据|個人資料)|(账户|帳戶|账号|个人数据|個人資料).{0,20}删除",
        r"(アカウント|個人データ|個人情報).{0,20}削除|削除.{0,20}(アカウント|個人データ|個人情報)",
        r"(계정|개인정보).{0,20}삭제|삭제.{0,20}(계정|개인정보)",
    ]
    NEGATIVE_PATTERNS = [
        r"\b(do not|don't|dont|not asking|not requesting|without)\b.{0,80}\b(delete|deletion|erase|erasure|remove)\b",
        r"\b(no quiero|no solicito|no estoy pidiendo)\b.{0,60}\b(eliminar|borrar|suprimir)\b",
        r"\b(ne demande pas|ne souhaite pas)\b.{0,60}\b(supprimer|effacer)\b",
    ]

    def authorizes_deletion(self, request_text: str) -> bool:
        text = norm(request_text)
        if not text:
            return False
        matched = any(re.search(pattern, text, flags=re.I) for pattern in self.DELETE_PATTERNS)
        explicitly_denied = any(re.search(pattern, text, flags=re.I) for pattern in self.NEGATIVE_PATTERNS)
        return matched and not explicitly_denied

    @staticmethod
    def status(has_violations: bool, account_absence_verified: bool, identity_ambiguous: bool = False) -> str:
        if has_violations or not account_absence_verified or identity_ambiguous:
            return "INCOMPLETE"
        return "COMPLETE"
