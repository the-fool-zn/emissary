from typing import List, Optional
from app.schemas import Mitre

TECHNIQUES = {
    "T1110": Mitre(id="T1110", name="Brute Force", tactic="Credential Access"),
    "T1078": Mitre(id="T1078", name="Valid Accounts", tactic="Initial Access"),
    "T1595": Mitre(id="T1595", name="Active Scanning", tactic="Reconnaissance"),
    "T1046": Mitre(id="T1046", name="Network Service Discovery", tactic="Discovery"),
    "T1190": Mitre(id="T1190", name="Exploit Public-Facing Application", tactic="Initial Access"),
}


def lookup_mitre(technique_id: str) -> Optional[Mitre]:
    return TECHNIQUES.get(technique_id.upper())


def techniques(*ids: str) -> List[Mitre]:
    return [TECHNIQUES[i] for i in ids if i in TECHNIQUES]
