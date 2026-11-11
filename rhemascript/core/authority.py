from dataclasses import dataclass

class AuthorityError(PermissionError):
    pass

# Consequential operations require explicit, scoped authorisation.
REQUIRED_AUTHORITY = {
    "GENERATE": "generation_authorisation",
    "PUBLISH": "publishing_authorisation",
    "SPEND": "spending_authorisation",
    "EXTERNAL_WRITE": "external_action_authorisation",
}

def authorise_action(action: str, approvals: dict[str, bool]) -> bool:
    key = REQUIRED_AUTHORITY.get(action)
    if key is None:
        raise AuthorityError(f"unknown consequential action: {action}")
    if approvals.get(key) is not True:
        raise AuthorityError(f"{action} requires explicit {key}")
    return True

def final_acceptance_allowed(*, human_director_acceptance: bool) -> bool:
    return human_director_acceptance is True
