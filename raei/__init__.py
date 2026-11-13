"""RhemaScript Engineering and AI Intelligence (RAEI) training foundation.

Curriculum definitions and project-specific learning records do not retrain model
weights. They provide controlled, evidence-linked practice and assessment.
"""
from .curriculum import CURRICULUM_VERSION, build_registry, registry_summary
from .knowledge import RAEIKnowledgeError, list_knowledge, record_knowledge, search_knowledge
from .training import (
    RAEITrainingError,
    build_self_assessment_payload,
    build_training_brief,
    get_progress,
    next_unit,
    record_attempt,
)

__all__ = [
    "CURRICULUM_VERSION", "build_registry", "registry_summary",
    "RAEIKnowledgeError", "list_knowledge", "record_knowledge", "search_knowledge",
    "RAEITrainingError", "build_self_assessment_payload", "build_training_brief", "get_progress",
    "next_unit", "record_attempt",
]
