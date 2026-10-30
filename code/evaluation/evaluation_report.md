# Evaluation Report

## Results

Commands were run with Python 3.12.10 on the participant-facing dataset.

- Public sample status accuracy: 32/32 (100%).
- Public sample exact step-array accuracy: 8/32 (25%).
- Public sample sequence accuracy: 8/32 (25%).
- Position-level step accuracy: 114/194 (58.8%).
- Field accuracy: 952/1,358 (70.1%).
- Evidence-reference accuracy: 158/194 (81.4%).
- Full output: 518 data rows, sorted, with the required header and zero structural validator errors.
- Full output status counts: COMPLETE 165, INCOMPLETE 300, NOT_APPLICABLE 53.
- Full output semantic warning: 20 COMPLETE rows have no evidence-backed verification step. These cases need additional evidence coverage or a better completeness decision before submission.
- Evidence extraction warnings: 11 PNG screenshots were not OCR-read because Tesseract was unavailable. Four PDFs were text-extracted with Poppler; SQL, JSON, text, and logs were parsed locally.

## Synthetic Cases

All five deterministic checks passed:

1. A historical email resolves to its stable user and current aliases.
2. A tombstone with direct identifiers is flagged for redaction while its stable reference is preserved.
3. An active connector produces a disable-flow action.
4. A restorable archive produces a block-restore action.
5. An in-retention security audit remains retained, and a marketing opt-out alone is not treated as a deletion request.

## Failures And Improvements

- Early status accuracy was 20/32. The intent classifier was expanded for multilingual deletion requests, “already removed” wording, and deletion audits, while explicit access, correction, export, and marketing-only requests remain non-deletion.
- Generic export filenames incorrectly overrode nested resource ownership. The parser now carries system names from JSON object keys and prefers explicit resource/table category information.
- Name substring matching linked similar people. Matching now uses exact email/user/hash/phone values and exact name fields, with alias history limited by `audit_at`.
- Activity operation results were initially considered state. `CHECK_*` claims are now excluded from findings; catalog identity links only connect to actual resources.
- Shared support conversations are redacted when exposed; standalone support attachments and legacy contact-index entries are deleted. Backups and active flows are handled before downstream cleanup in the ordered plan.
- After these changes, sample status accuracy reached 32/32, but exact step-array accuracy remains 8/32. Some expected sample verification steps have no matching evidence record in the evidence parser, and there are still disagreements in supported resource treatment. These are unresolved semantic failures, not a passing submission result.
- Twenty full-dataset rows are still marked COMPLETE without a supporting verification step. Do not submit these predictions as final until identity/resource links or the decision logic are improved.
