class DisclosureError(PermissionError):
    pass

LEVELS = {"OPERATIONAL": 1, "CONTROLLED": 2, "PROTECTED": 3}

def disclose(*, item_classification: str, recipient_clearance: str,
             task_need: bool, approved_scope: bool) -> bool:
    if item_classification not in LEVELS or recipient_clearance not in LEVELS:
        raise DisclosureError("unknown information classification")
    if not task_need or not approved_scope:
        raise DisclosureError("minimum-necessary disclosure conditions not met")
    if LEVELS[recipient_clearance] < LEVELS[item_classification]:
        raise DisclosureError("recipient clearance is insufficient")
    return True
