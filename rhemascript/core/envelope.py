from typing import Any

REQUIRED_FIELDS = {
    "record_id", "record_type", "schema_version", "project_id",
    "status", "classification", "version"
}
VALID_STATUSES = {
    "DRAFT", "UNDER_REVIEW", "APPROVED", "AUTHORISED", "EXECUTED",
    "VERIFIED", "ACCEPTED", "ON_HOLD", "BLOCKED", "REJECTED",
    "SUPERSEDED", "ARCHIVED", "CANCELLED"
}
VALID_CLASSIFICATIONS = {"OPERATIONAL", "CONTROLLED", "PROTECTED"}

class ContractError(ValueError):
    pass

def validate_record(record: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise ContractError("record must be an object")
    missing = REQUIRED_FIELDS - record.keys()
    if missing:
        raise ContractError(f"missing required fields: {', '.join(sorted(missing))}")
    for field in ("record_id", "record_type", "schema_version", "project_id", "version"):
        if not isinstance(record[field], str) or not record[field].strip():
            raise ContractError(f"{field} must be a non-empty string")
    if record["status"] not in VALID_STATUSES:
        raise ContractError("invalid lifecycle status")
    if record["classification"] not in VALID_CLASSIFICATIONS:
        raise ContractError("invalid information classification")
    return record
