"""Versioned RAEI mastery curriculum; registry definition is not proof of competence."""
from __future__ import annotations

CURRICULUM_VERSION = "RAEI-CURRICULUM-1.0"

BIBLE_BOOKS = [
    "Genesis", "Exodus", "Leviticus", "Numbers", "Deuteronomy", "Joshua", "Judges", "Ruth",
    "1 Samuel", "2 Samuel", "1 Kings", "2 Kings", "1 Chronicles", "2 Chronicles", "Ezra", "Nehemiah", "Esther",
    "Job", "Psalms", "Proverbs", "Ecclesiastes", "Song of Songs", "Isaiah", "Jeremiah", "Lamentations", "Ezekiel", "Daniel",
    "Hosea", "Joel", "Amos", "Obadiah", "Jonah", "Micah", "Nahum", "Habakkuk", "Zephaniah", "Haggai", "Zechariah", "Malachi",
    "Matthew", "Mark", "Luke", "John", "Acts", "Romans", "1 Corinthians", "2 Corinthians", "Galatians", "Ephesians",
    "Philippians", "Colossians", "1 Thessalonians", "2 Thessalonians", "1 Timothy", "2 Timothy", "Titus", "Philemon",
    "Hebrews", "James", "1 Peter", "2 Peter", "1 John", "2 John", "3 John", "Jude", "Revelation",
]

ENGINEERING = [
    ("CS-FOUND", "Computer science foundations"),
    ("PROG-CORE", "Programming and original-code fluency"),
    ("ALGO-DS", "Algorithms and data structures"),
    ("OS-CONC", "Operating systems and concurrency"),
    ("DB-TXN", "Databases, transactions and recovery"),
    ("NETWORK", "Networking, DNS, HTTP and TLS"),
    ("DIST-SYS", "Distributed systems, queues and idempotency"),
    ("SECURE-CODE", "Secure coding and threat modelling"),
    ("FRONTEND", "Frontend architecture, state and accessibility"),
    ("BACKEND-API", "Backend services and API design"),
    ("TESTING", "Unit, integration and end-to-end testing"),
    ("DEVOPS", "Build, CI, observability and operations"),
    ("SYSTEM-DESIGN", "System design and architecture rationale"),
    ("AI-ML-FOUNDATIONS", "Artificial intelligence and machine-learning foundations"),
    ("LLM-SYSTEMS", "Language models, inference, context and limitations"),
    ("RAG-KNOWLEDGE", "Retrieval, knowledge stores, citations and provenance"),
    ("AGENT-ORCHESTRATION", "Agent planning, tool use, permissions and sandboxing"),
    ("AI-EVALUATION", "Model evaluation, adversarial testing and reliability"),
    ("MLOPS-GOVERNANCE", "Model lifecycle, monitoring, governance and change control"),
    ("CAPSTONE-FULLSTACK", "Integrated frontend/backend/database capstone"),
    ("CAPSTONE-SECURITY", "Authentication, authorization and secure API capstone"),
    ("CAPSTONE-RELIABILITY", "Concurrency, failure recovery, audit and backup/restore capstone"),
    ("CAPSTONE-REPRODUCIBLE", "Reproducible build and operational handover capstone"),
]

ETHICS_CASES = [
    ("ETH-TRUTH", "Truthfulness, provenance and correction"),
    ("ETH-STEWARD", "Stewardship of resources and entrusted capability"),
    ("ETH-JUSTICE", "Justice, impartiality and fair treatment"),
    ("ETH-COMPASSION", "Compassion and care for vulnerable people"),
    ("ETH-ACCOUNT", "Accountability, confession and correction"),
    ("ETH-PRIVACY", "Privacy, confidentiality and restraint"),
    ("ETH-AUTHORITY", "Authority, obedience and misuse of power"),
    ("ETH-DECEPTION", "Deception, manipulation and false claims"),
    ("ETH-HARM", "Foreseeable harm and protection of neighbour"),
    ("ETH-TECH", "Responsible use of technology under biblical principles"),
]

RHEMA_CAPABILITIES = [(f"CAP-{n:02d}", f"RhemaScript capability CAP-{n:02d}") for n in range(1, 16)]
RHEMA_INTERFACES = [(f"IF-{n:02d}", f"RhemaScript interface IF-{n:02d}") for n in range(1, 19)]
RHEMA_SPECIALISTS = [
    ("RS-CIE", "Content Intelligence Engine"),
    ("TISR", "Topic Intelligence and Strategic Recommendation"),
    ("YCSAI", "YouTube Content Strategy and Audience Intelligence"),
    ("VBAP", "Visual-to-Biblical Alignment Protocol"),
    ("LSLS", "Language Selection and Localization Standard"),
    ("PPE", "Precision Prompt Engineering"),
    ("PAF", "Prompt Audit Framework"),
    ("CAPWF", "Controlled AI Project Working Flow"),
    ("SIX-GATES", "Six approval gates and authorization boundaries"),
    ("P0-GOV", "P0 security governance foundation"),
    ("SOURCE-CHAIN", "Source-to-Final Integrity Chain"),
    ("ASSET-FIRST", "Asset-first editing and generation restraint"),
    ("QC-COMPLIANCE", "Quality control and YouTube compliance"),
]

RUBRIC = ("accuracy", "reasoning", "execution", "evidence")


def _unit(uid: str, title: str, domain: str, objectives: list[str],
          source_refs: list[str], practice_prompt: str) -> dict:
    return {
        "id": uid,
        "title": title,
        "domain": domain,
        "curriculum_version": CURRICULUM_VERSION,
        "objectives": list(objectives),
        "source_refs": list(source_refs),
        "practice_prompt": practice_prompt,
        "rubric": list(RUBRIC),
        "evidence_required": True,
        "prerequisites": [],
    }


def build_registry() -> list[dict]:
    units: list[dict] = []
    for uid, title in ENGINEERING:
        units.append(_unit(
            uid, title, "engineering",
            ["Explain core concepts and trade-offs", "Implement an original solution",
             "Test normal, boundary and failure paths", "Document limitations and security implications"],
            ["Versioned authoritative technical documentation", "RhemaScript engineering source and test evidence"],
            "Complete an original RhemaScript-relevant engineering task; retain source, tests, execution output and limitations.",
        ))
    for index, book in enumerate(BIBLE_BOOKS, 1):
        units.append(_unit(
            f"BIBLE-{index:02d}", book, "whole_bible",
            ["Identify setting, genre and structure", "Explain themes and key passages in context",
             "Relate the book canonically and identify interpretive risks", "Answer comprehension questions"],
            ["Biblical text with exact translation/version recorded; HINOVBSI for direct Hindi quotations",
             "Historical and literary context sources with source/version provenance"],
            "Produce a contextual book study with passage analysis, canonical links, interpretation cautions and answered questions.",
        ))
    for uid, title in ETHICS_CASES:
        units.append(_unit(
            uid, title, "bible_only_ethics",
            ["Identify relevant passages in context", "Distinguish explicit Scripture from inference",
             "State uncertainty and justify a decision using biblical principles only"],
            ["Biblical text; relevant passages selected and justified in the case record"],
            "Resolve a concrete RhemaScript/RAEI scenario using contextual biblical reasoning; document alternatives and risks.",
        ))
    for uid, title in RHEMA_CAPABILITIES + RHEMA_INTERFACES + RHEMA_SPECIALISTS:
        units.append(_unit(
            uid, title, "rhemascript",
            ["Explain the current approved specification and version", "Demonstrate correct workflow use",
             "Preserve approval, evidence and authorization boundaries"],
            ["RhemaScript POS V1.4 and exact approved module specifications"],
            "Complete a traceable RhemaScript simulation using existing controls; do not generate media or publish.",
        ))
    units.append(_unit(
        "INTEGRATED-CAPSTONE", "Integrated readiness capstone", "integrated",
        ["Combine full-stack controls, contextual Bible interpretation and Bible-only ethics",
         "Demonstrate RhemaScript governance and source-to-final traceability",
         "Report limitations, unresolved assurance and authority boundaries"],
        ["All prerequisite units and their independently reviewed evidence"],
        "Simulate one end-to-end RhemaScript project from biblical source to final-film readiness without media generation or publication.",
    ))

    by_domain: dict[str, list[dict]] = {}
    for item in units:
        by_domain.setdefault(item["domain"], []).append(item)
    previous_domain_final = None
    for domain, domain_units in by_domain.items():
        for index, item in enumerate(domain_units):
            if index:
                item["prerequisites"] = [domain_units[index - 1]["id"]]
            elif previous_domain_final:
                item["prerequisites"] = [previous_domain_final]
        if domain != "integrated":
            previous_domain_final = domain_units[-1]["id"]
    units[-1]["prerequisites"] = [
        domain_units[-1]["id"] for domain, domain_units in by_domain.items() if domain != "integrated"
    ]

    identifiers = [item["id"] for item in units]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("duplicate curriculum unit identifier")
    return units


def registry_summary() -> dict:
    units = build_registry()
    counts: dict[str, int] = {}
    for unit in units:
        counts[unit["domain"]] = counts.get(unit["domain"], 0) + 1
    return {
        "curriculum_version": CURRICULUM_VERSION,
        "total_units": len(units),
        "by_domain": counts,
        "bible_book_count": len(BIBLE_BOOKS),
        "ethics_case_count": len(ETHICS_CASES),
        "capability_count": len(RHEMA_CAPABILITIES),
        "interface_count": len(RHEMA_INTERFACES),
        "specialist_count": len(RHEMA_SPECIALISTS),
        "status": "CURRICULUM_DEFINED_NOT_ASSESSED",
    }
