"""Canonical RAEI curriculum registry. Registry entries are NOT evidence of mastery."""
from __future__ import annotations

BIBLE_BOOKS = [
"Genesis","Exodus","Leviticus","Numbers","Deuteronomy","Joshua","Judges","Ruth",
"1 Samuel","2 Samuel","1 Kings","2 Kings","1 Chronicles","2 Chronicles","Ezra","Nehemiah","Esther",
"Job","Psalms","Proverbs","Ecclesiastes","Song of Songs","Isaiah","Jeremiah","Lamentations","Ezekiel","Daniel",
"Hosea","Joel","Amos","Obadiah","Jonah","Micah","Nahum","Habakkuk","Zephaniah","Haggai","Zechariah","Malachi",
"Matthew","Mark","Luke","John","Acts","Romans","1 Corinthians","2 Corinthians","Galatians","Ephesians",
"Philippians","Colossians","1 Thessalonians","2 Thessalonians","1 Timothy","2 Timothy","Titus","Philemon",
"Hebrews","James","1 Peter","2 Peter","1 John","2 John","3 John","Jude","Revelation"
]

ENGINEERING = [
("CS-FOUND","Computer science foundations"),("PROG-CORE","Programming and original-code fluency"),
("ALGO-DS","Algorithms and data structures"),("OS-CONC","Operating systems and concurrency"),
("DB-TXN","Databases, transactions and recovery"),("NETWORK","Networking, DNS, HTTP and TLS"),
("DIST-SYS","Distributed systems, queues and idempotency"),("SECURE-CODE","Secure coding and threat modelling"),
("FRONTEND","Frontend architecture, state and accessibility"),("BACKEND-API","Backend services and API design"),
("TESTING","Unit, integration and end-to-end testing"),("DEVOPS","Build, CI, observability and operations"),
("SYSTEM-DESIGN","System design and architecture rationale"),
("CAPSTONE-FULLSTACK","Integrated frontend/backend/database capstone"),
("CAPSTONE-SECURITY","Authentication, authorization and secure API capstone"),
("CAPSTONE-RELIABILITY","Concurrency, failure recovery, audit and backup/restore capstone"),
("CAPSTONE-REPRODUCIBLE","Reproducible build and operational handover capstone")
]

ETHICS_CASES = [
("ETH-TRUTH","Truthfulness, provenance and correction"),
("ETH-STEWARD","Stewardship of resources and entrusted capability"),
("ETH-JUSTICE","Justice, impartiality and fair treatment"),
("ETH-COMPASSION","Compassion and care for vulnerable people"),
("ETH-ACCOUNT","Accountability, confession and correction"),
("ETH-PRIVACY","Privacy, confidentiality and restraint"),
("ETH-AUTHORITY","Authority, obedience and misuse of power"),
("ETH-DECEPTION","Deception, manipulation and false claims"),
("ETH-HARM","Foreseeable harm and protection of neighbour"),
("ETH-TECH","Responsible use of technology under biblical principles")
]

RHEMA_CAPABILITIES = [("CAP-%02d" % n, "RhemaScript capability CAP-%02d" % n) for n in range(1,16)]
RHEMA_INTERFACES = [("IF-%02d" % n, "RhemaScript interface IF-%02d" % n) for n in range(1,19)]
RHEMA_SPECIALISTS = [
("RS-CIE","Content Intelligence Engine"),("TISR","Topic Intelligence and Strategic Recommendation"),
("YCSAI","YouTube Content Strategy and Audience Intelligence"),("VBAP","Visual-to-Biblical Alignment Protocol"),
("LSLS","Language Selection and Localization Standard"),("PPE","Precision Prompt Engineering"),
("PAF","Prompt Audit Framework"),("CAPWF","Controlled AI Project Working Flow"),
("SIX-GATES","Six approval gates and authorization boundaries"),("P0-GOV","P0 security governance foundation"),
("SOURCE-CHAIN","Source-to-Final Integrity Chain"),("ASSET-FIRST","Asset-first editing and generation restraint"),
("QC-COMPLIANCE","Quality control and YouTube compliance")
]

def _unit(uid, title, domain, objective, sources, practice, rubric):
    return {"id": uid, "title": title, "domain": domain, "status": "not_started",
            "objectives": objective, "source_refs": sources, "practice_prompt": practice,
            "rubric": rubric, "evidence_required": True}

def build_registry():
    rubric = ["accuracy", "reasoning", "execution", "evidence"]
    units = []
    for uid, title in ENGINEERING:
        units.append(_unit(uid,title,"engineering",
            ["Explain the core concepts and trade-offs", "Implement an original solution", "Test normal and failure paths"],
            ["RAEI engineering competency framework", "Relevant language/runtime and protocol documentation"],
            "Write original code for a RhemaScript-relevant task; include tests, execution command, output and limitations.",rubric))
    for index, book in enumerate(BIBLE_BOOKS,1):
        uid = "BIBLE-%02d" % index
        units.append(_unit(uid,book,"whole_bible",
            ["Identify setting, genre and structure", "Explain themes and key passages in context",
             "Relate the book canonically and identify interpretive risks", "Answer comprehension questions"],
            ["The complete biblical text in the selected translation", "Relevant historical and literary context sources"],
            "Produce a book study with contextual passage analysis, canonical links, interpretation cautions and answered questions.",rubric))
    for uid,title in ETHICS_CASES:
        units.append(_unit(uid,title,"bible_only_ethics",
            ["Identify relevant passages in context", "Compare Scripture and distinguish explicit teaching from inference",
             "State uncertainty and justify a decision without importing an alternate moral authority"],
            ["Biblical text; relevant passages must be selected and justified in the case record"],
            "Resolve a concrete RhemaScript/RAEI scenario using contextual biblical reasoning; document alternatives and risks.",rubric))
    for uid,title in RHEMA_CAPABILITIES + RHEMA_INTERFACES + RHEMA_SPECIALISTS:
        units.append(_unit(uid,title,"rhemascript",
            ["Explain the existing approved specification", "Demonstrate correct workflow use", "Preserve approval and evidence boundaries"],
            ["RhemaScript POS V1.4 and the applicable approved module specification"],
            "Complete a traceable RhemaScript simulation using existing controls; do not generate media or publish.",rubric))
    units.append(_unit("INTEGRATED-CAPSTONE","Integrated readiness capstone","integrated",
        ["Combine full-stack controls, contextual Bible interpretation and Bible-only ethics",
         "Demonstrate RhemaScript governance and source-to-final traceability",
         "Report limitations, unresolved assurance and authority boundaries"],
        ["All passed prerequisite units and their inspectable evidence"],
        "Simulate one end-to-end RhemaScript project from biblical source to final-film readiness without media generation or publication.",rubric))
    # Enforce the declared programme sequence in the ledger itself. A UI/domain
    # ordering is not a prerequisite control: direct assessment calls must also
    # be unable to bypass earlier units.
    by_domain = {}
    for item in units:
        by_domain.setdefault(item["domain"], []).append(item)
    for domain_units in by_domain.values():
        for index, item in enumerate(domain_units):
            item["prerequisites"] = [domain_units[index - 1]["id"]] if index else []
    final_domain_units = [items[-1]["id"] for items in by_domain.values()]
    units[-1]["prerequisites"] = final_domain_units

    ids=[u["id"] for u in units]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate curriculum unit identifier")
    return units

def registry_summary():
    units=build_registry()
    counts={}
    for unit in units:
        counts[unit["domain"]]=counts.get(unit["domain"],0)+1
    return {"total_units":len(units),"by_domain":counts,"bible_book_count":len(BIBLE_BOOKS),
            "ethics_case_count":len(ETHICS_CASES),"capability_count":len(RHEMA_CAPABILITIES),
            "interface_count":len(RHEMA_INTERFACES),"specialist_count":len(RHEMA_SPECIALISTS),
            "status":"curriculum_defined_not_assessed"}
