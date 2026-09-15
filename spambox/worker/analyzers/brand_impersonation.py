"""Rilevazione di impersonificazione di brand noti (spoofing del nome
visualizzato).

Diverso dal lookalike "classico" (che confronta la SOMIGLIANZA testuale tra
il dominio del mittente e i domini protetti dell'azienda, per il
typosquatting): qui si controlla se il messaggio si spaccia per un brand
terzo molto noto (corrieri, banche, big tech...) tramite il nome
visualizzato ("From: DHL <...>"), mentre il dominio reale del mittente non
ha nulla a che vedere con quel brand. È la tecnica classica delle truffe
"pacco in consegna"/"conto bloccato" che impersonano DHL, Poste Italiane,
PayPal, ecc. — aziende che non fanno parte dei domini protetti
dell'organizzazione (quelli sono gestiti separatamente, vedi lookalike.py).

L'elenco qui sotto è un default ragionevole dei brand più comunemente
impersonati in Italia; per aggiungerne altri basta estendere il dizionario.
"""
from __future__ import annotations

from dataclasses import dataclass

# brand (minuscolo, come compare nel nome visualizzato) -> domini legittimi
KNOWN_BRANDS: dict[str, list[str]] = {
    "dhl": ["dhl.com", "dhl.it", "dhl.de"],
    "ups": ["ups.com"],
    "fedex": ["fedex.com"],
    "poste italiane": ["poste.it"],
    "poste": ["poste.it"],
    "bartolini": ["bartolini.it", "brt.it"],
    "brt": ["brt.it"],
    "gls": ["gls-italy.com", "gls-group.com"],
    "sda": ["sda.it"],
    "paypal": ["paypal.com"],
    "amazon": ["amazon.it", "amazon.com", "amazon.de", "amazon.fr"],
    "netflix": ["netflix.com"],
    "microsoft": ["microsoft.com", "outlook.com", "live.com"],
    "apple": ["apple.com", "icloud.com"],
    "google": ["google.com", "gmail.com"],
    "intesa sanpaolo": ["intesasanpaolo.com"],
    "unicredit": ["unicredit.it", "unicredit.eu"],
    "agenzia delle entrate": ["agenziaentrate.gov.it"],
    "inps": ["inps.it"],
    # Utility ed enti pubblici italiani, bersaglio molto comune di truffe
    # "rimborso"/"bolletta anomala"/"conguaglio"
    "enel": ["enel.it", "enel.com"],
    "enel energia": ["enel.it", "enel.com"],
    "eni": ["eni.it", "eni.com"],
    "eni plenitude": ["eni.it", "plenitude.com"],
    "a2a": ["a2a.it", "a2aenergia.eu"],
    "acea": ["acea.it"],
    "hera": ["gruppohera.it"],
    "iren": ["gruppoiren.it"],
    "tim": ["tim.it"],
    "vodafone": ["vodafone.it"],
    "windtre": ["windtre.it"],
    "wind tre": ["windtre.it"],
    "iliad": ["iliad.it"],
    "fastweb": ["fastweb.it"],
    "equitalia": ["agenziaentrateriscossione.gov.it"],
    "agenzia delle entrate riscossione": ["agenziaentrateriscossione.gov.it"],
}


@dataclass
class BrandImpersonationMatch:
    claimed_brand: str
    sender_domain: str
    legitimate_domains: list[str]


def find_brand_impersonation(
    quoted_senders: list[tuple[str, str]],
) -> list[BrandImpersonationMatch]:
    """Per ogni (nome visualizzato, dominio) annidato nel forward, verifica
    se il nome dichiara un brand noto ma il dominio non è tra quelli
    legittimi di quel brand."""
    matches: list[BrandImpersonationMatch] = []
    seen: set[tuple[str, str]] = set()

    for display_name, domain in quoted_senders:
        if not display_name or not domain:
            continue
        name_lower = display_name.lower()
        for brand, legit_domains in KNOWN_BRANDS.items():
            if brand not in name_lower:
                continue
            is_legit = any(
                domain == d or domain.endswith("." + d) for d in legit_domains
            )
            if not is_legit and (brand, domain) not in seen:
                seen.add((brand, domain))
                matches.append(
                    BrandImpersonationMatch(
                        claimed_brand=brand, sender_domain=domain, legitimate_domains=legit_domains
                    )
                )

    return matches
