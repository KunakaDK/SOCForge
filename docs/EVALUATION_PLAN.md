# SOCForge evaluation plan

## Objective

Measure whether the prototype ingests representative events, creates expected alerts, allows an analyst workflow to be recorded and preserves audit-chain integrity.

## Repeatable functional checks

1. Start the API with a fresh local database.
2. Replay the deterministic synthetic dataset using `python -m socforge simulate`.
3. Confirm that event count increases and the detection engine creates alerts for the controlled test cases.
4. Acknowledge at least one alert and add an analyst note.
5. Create an incident linked to the alert and move it through investigation to resolution.
6. Add a synthetic vulnerability finding and update its status.
7. Run the audit verification endpoint and confirm the chain is valid.
8. Run `pytest` and retain the output with the portfolio report.

## Detection metrics

Use a labelled evaluation set and report a confusion matrix.

- Precision = TP / (TP + FP)
- Recall = TP / (TP + FN)
- F1 = 2 * precision * recall / (precision + recall)
- False-positive rate = FP / (FP + TN)
- Mean time to detect = detection timestamp - event timestamp
- Mean time to acknowledge = acknowledgement timestamp - alert creation timestamp

Do not report accuracy alone when the benign/malicious class balance is uneven.

## Evidence to publish

- Reproducible dataset generation seed and dataset description
- Detection catalogue and rule versions
- Test command and raw test output
- Screenshots of dashboard and alert lifecycle
- Sample incident report with synthetic identifiers
- Audit-chain verification output
- Known limitations and false-positive examples

All results must be labelled as synthetic-lab results unless validated against an authorised real-world dataset.
