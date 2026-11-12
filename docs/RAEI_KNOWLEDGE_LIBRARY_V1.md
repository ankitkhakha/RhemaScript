# RAEI Knowledge Intake and Learning Library V1.0

## Knowledge lifecycle

1. A source is acquired through an approved manual or local workflow.
2. The exact source artifact is retained under the configured evidence root.
3. The artifact verifier checks existence and SHA-256 and returns an exact process-verified EvidenceVersion.
4. RAEI creates a canonical knowledge record containing source identity/version, authority level, summary, claims, limitations, tags and exact evidence ID/version.
5. The knowledge item is recorded as **PENDING_REVIEW** only.
6. An authenticated human review mechanism must approve it before the production knowledge search can use it.
7. A corrected or updated source creates a new version; the old record remains and is referenced through `supersedes`.

## Trust boundaries

- A matching SHA-256 proves which bytes were retained; it does not prove that the source is authentic, authoritative or relevant to a claim.
- The intake layer therefore fixes `source_authentication_status=NOT_CHECKED` and `claim_relevance_status=NOT_ASSESSED`.
- RAEI cannot set a new item to APPROVED. Status forgery is rejected when the knowledge library is read.
- New knowledge is never allowed to grant project approval, execution authority, media-generation permission or publishing permission.
- Direct Hindi Scripture quotations must use the approved HINOVBSI wording. Every Bible item records its translation/version.

## Source categories

- `BIBLE`: biblical text, translation/version, book and passage context.
- `OFFICIAL_DOC`: primary official technical documentation.
- `INTERNAL_SPEC`: approved RhemaScript/RAEI specifications and revisions.
- `CODE`: exact source code or test artifacts.
- `SECONDARY`: commentary or secondary research, clearly labelled.
- `LESSON_FROM_FAILURE`: retained failure, root cause, remediation and regression-test references.

Authority labels distinguish Scripture, official primary sources, approved internal specifications, secondary sources and unverified material. They are metadata for review, not automatic truth scores.

## Continuous improvement loop

- **Acquisition:** capture a new source or approved lesson.
- **Verification:** retain exact bytes and verify the evidence digest.
- **Review:** assess source authority, claim relevance, freshness and contradictions.
- **Approval:** require authenticated human review; pending material is not used as approved knowledge.
- **Practice:** link approved knowledge to a curriculum unit and practical task.
- **Assessment:** retain rubric scores and test evidence.
- **Remediation:** preserve failures and create a new lesson version; never overwrite prior evidence.
- **Refresh:** re-review knowledge when sources, code, architecture or standards change.

## Current limitation

Training briefs surface pending items for review but never treat them as approved sources. This feature implements evidence-bound intake and pending-review search. It does not yet implement signed human knowledge approval or automatic source acquisition. Those are separate, controlled steps. No paid API, external connector or background model-weight training is used.
