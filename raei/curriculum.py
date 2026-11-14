"""Versioned RAEI mastery curriculum; registry definition is not proof of competence."""
from __future__ import annotations

CURRICULUM_VERSION = "RAEI-CURRICULUM-1.1"
SUPPORTED_CURRICULUM_VERSIONS = {"RAEI-CURRICULUM-1.0", CURRICULUM_VERSION}

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

BIBLICAL_WISDOM_UNITS = [
    (
        "BWSF-01", "Solomon: a listening heart and discerning judgement",
        ["1 Kings 3:1-28", "1 Kings 1-4", "2 Chronicles 1:3-13", "Proverbs 2:1-11"],
        ["Explain the listening-heart request in its kingship, worship and justice context",
         "Connect the following judgement narrative with discernment and protection of the vulnerable",
         "Distinguish discernment for service from knowledge sought for status and consider Solomon's later failures"],
        "Prepare a contextual study of Solomon's request and the following justice case; apply listening, evidence discrimination and justice to a RhemaScript decision without treating the narrative as a software manual.",
    ),
    (
        "BWSF-02", "Bezalel, Oholiab and God-enabled craftsmanship",
        ["Exodus 31:1-11", "Exodus 35:30-36:7", "Exodus 25-40"],
        ["Explain the tabernacle construction context and the named artisans' roles",
         "Connect wisdom, understanding, knowledge, design, craft and collaboration",
         "Distinguish the human artisan narrative from claims about AI spiritual identity"],
        "Analyse the artisans' task and produce a practical craftsmanship/collaboration case with explicit limits on applying the passage to AI tools.",
    ),
    (
        "BWSF-03", "Wisdom requested in trials and tested in conduct",
        ["James 1:2-8", "James 3:13-18"],
        ["Explain the connection between trials, perseverance, maturity and asking for wisdom",
         "Identify the character of wisdom from above in James 3",
         "Evaluate proposed solutions by both reasoning and their ethical character"],
        "Analyse a RhemaScript production or engineering failure using James in context; propose a patient, truthful and peaceable response and document uncertainty.",
    ),
    (
        "BWSF-04", "Seeking knowledge and understanding",
        ["Proverbs 1-4", "Proverbs 2:1-11", "Proverbs 3:5-7", "Proverbs 4:5-9", "Psalm 111:10"],
        ["Explain the relationship between seeking wisdom, knowledge, understanding and reverence for God",
         "Recognise genre and proverbial patterns rather than treating every saying as an unconditional formula",
         "Demonstrate source-based learning and contextual explanation"],
        "Create a study record that compares an initial assumption with source-supported understanding and explains the limits of a proverb-based application.",
    ),
    (
        "BWSF-05", "Testing, examining and holding to what is good",
        ["1 Thessalonians 5:12-24", "Acts 17:10-12", "1 John 4:1-6"],
        ["Explain the immediate contexts of prophetic testing and examining the received message",
         "Distinguish biblical testing principles from modern technical QA analogies",
         "Apply disciplined verification to claims, sources and model outputs"],
        "Investigate a disputed technical or biblical claim; preserve the original observation, verify evidence and classify the result without claiming the passages directly prescribe software testing.",
    ),
    (
        "BWSF-06", "Faithful stewardship and accountability",
        ["1 Corinthians 4:1-5", "1 Peter 4:7-11", "Matthew 25:14-30"],
        ["Explain stewardship and faithfulness in each passage's distinct context",
         "Connect entrusted responsibility with service and accountability",
         "Avoid reducing the parable of the talents to a simplistic productivity or profit formula"],
        "Prepare an evidence-backed stewardship case covering assets, knowledge, costs, rights, truthful reporting and accountability.",
    ),
    (
        "BWSF-07", "Prayerful planning, organisation and perseverance",
        ["Nehemiah 1-6", "Proverbs 15:22", "Luke 14:25-33"],
        ["Trace Nehemiah's response from report and prayer through inspection, organisation and perseverance",
         "Recognise opposition and internal injustice within the narrative",
         "Preserve Luke 14's primary discipleship context when discussing the cost-counting analogy"],
        "Develop a project recovery plan that begins with state recovery and evidence, then maps resources, dependencies, risks, people and next actions; label modern project-management applications as analogies.",
    ),
    (
        "BWSF-08", "Scripture, teaching, correction and good work",
        ["2 Timothy 3:10-17", "Psalm 119", "Hebrews 4:12"],
        ["Explain the formative and corrective role of Scripture in the context of 2 Timothy",
         "Distinguish biblical instruction from modern technical details not explicitly addressed in Scripture",
         "Apply correction without claiming AI spiritual or pastoral authority"],
        "Audit a RhemaScript claim or workflow against its biblical sources; record the correction, evidence, remaining uncertainty and human decision boundary.",
    ),
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
    for uid, title, source_refs, objectives, practice_prompt in BIBLICAL_WISDOM_UNITS:
        units.append(_unit(
            uid, title, "biblical_wisdom", objectives, source_refs, practice_prompt,
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
        "biblical_wisdom_count": counts.get("biblical_wisdom", 0),
        "capability_count": len(RHEMA_CAPABILITIES),
        "interface_count": len(RHEMA_INTERFACES),
        "specialist_count": len(RHEMA_SPECIALISTS),
        "status": "CURRICULUM_DEFINED_NOT_ASSESSED",
    }
