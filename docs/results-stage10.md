# HetNet Stage 10 — labeled aggregate source/lineage holdout results

Date: 2026-11-19 (research continuation; CI logs dated 2026-11-18 UTC).
Reproducible GitHub Actions run:
https://github.com/verge88/HetNet/actions/runs/44382530668

The above run completed **158 unit/integration tests on Python 3.10
and 3.12** and executed the labeled-eval CLI with export of
hetnet-stage10-labeled-aggregate. All results below use **ONLY
SYNTHETIC demonstration files**, never real operator data.

## Setup

Two all-normal training aggregate sources:
- lab_clean_alpha — source lineage lab_lineage_alpha
- lab_clean_beta — source lineage lab_lineage_beta

Two held-out annotated aggregate sources:
- lab_holdout_gamma — two manipulated reports (msc2 2G and amf5 5G),
  with all declared verification flags present
- lab_holdout_delta — two manipulated reports (mme4 4G and pcscf IMS)
  with verification unavailable throughout the window; one other
  normal node is unavailable; the remaining three normal nodes have
  exactly the same 10%-of-reference systematic counter offset.
  This is an intentionally designed common-mode benign bias stress case.

All four files have six monitored nodes and six relative intervals,
one coarse operation class per node per interval (36 rows per file).
Ground truth is assigned per node for the **whole dataset window**.
There is no intermittent attack onset, no raw signaling packets,
subscriber identities, physical sensor provenance or signatures.
The aggregate cu_verified_claim and quorum_verified_claim values
are user-provided flags, **not cryptographically verified claims**.

Threshold calibration is based only on the two normal training
sources, and did not use holdout data or attack-positive labels.
The resulting thresholds for zone_absolute and zone_peer were
both **1e-12**, since the persistent normal training scores were zero.
This is an artifact of a tiny synthetic benchmark; it is not a robust,
operator-calibrated decision threshold.

## Overall results on held-out sources

Exactly **12 node-level examples per detector**, of which 4 have
positive attack labels and 8 are normal. Three examples (two attacked,
one normal) had no two consecutive eligible measurements and
resulted in **abstention**, not a normal classification.
Nine examples had decisions: two attacked and seven normal.

| Metric | CU claimed baseline | Zone absolute | Zone peer (leave-one-out) |
|---|---:|---:|---:|
| Node examples | 12 | 12 | 12 |
| Decided examples | 9 | 9 | 9 |
| Abstentions | 3 | 3 | 3 |
| Coverage | 75% | 75% | 75% |
| TP | 2 | 2 | 2 |
| FP | 3 | 3 | 0 |
| FN on decided examples | 0 | 0 | 0 |
| TN | 4 | 4 | 7 |
| Precision, decided examples | 40% | 40% | 100% |
| Recall, decided examples | 100% | 100% | 100% |
| FPR, decided examples | 42.86% | 42.86% | 0% |
| F1, decided examples | 57.14% | 57.14% | 100% |
| Recall over all attacks (abstentions = misses) | **50%** | **50%** | **50%** |

The apparent 100% decided-only precision of Zone Peer is
**not** an external validated performance claim: all normal
reported offsets in the degraded fixture were deliberately
equal, so peer subtraction removes them exactly.
A broad attack against many similarly distorted nodes could
also disappear under common-mode peer subtraction.
With only seven decided negative examples, an observed
zero FPR offers no statistically meaningful guarantee.

The two attacked nodes in the degraded holdout were
**abstained** by all detectors. None was counted as a TN
or successful attack detection. Reporting only decided-only
recall would incorrectly conceal this degradation.

## What Stage 10 verifies

- A strictly bounded local JSON schema with only allowed
  coarse node/class/relative interval/count/claim fields.
- Clean-only train fit and source_id + lineage_id separation.
- Detection of literal copied measurement payloads even after
  source and lineage IDs are renamed.
- Separation of labels from the *feature* and *detector*
  functions; swapping holdout labels does not change scores
  or thresholds.
- Two adjacent eligible measurement intervals are required.
- Insufficient CU/quorum claims produce abstentions,
  counted separately from confusion metrics.
- Export includes only aggregate per-source and overall
  evaluations, thresholds and input fingerprints, **not**
  raw measurements or per-node attack labels.

## Limitations that must not be omitted

This is **not an independent operator experiment**.
All four datasets are explicitly synthetic; source and lineage
pseudonyms and SHA-256 values do not prove physical independence,
no-overlap of transformed traces, lawful provenance or the
correctness of external expert annotations. No actual signed CU
payloads or keys are present in the imported format.
The Stage 10 baseline is therefore called
cu_claimed_baseline, **not** signed-CU verified baseline.

The 20-event minimum is not k-anonymity. Any real aggregates
or annotations need separate legal/privacy authorization
and documented provenance. Do not commit real operator data
to public GitHub or CI.

The original dissertation motivates node/zone research, but
this work does not reproduce its ML models, independent test
results or operational detection rates. There is no certified
3GPP Release 18 conformance/interop test of real GSM/UMTS/
LTE/NR signaling stacks.

Method and input schema: docs/validation-stage10.md.

Reproduce:

    python -m hetnet labeled-audit \
      --input examples/labeled/lab_clean_alpha.json

    python -m hetnet labeled-eval \
      --train examples/labeled/lab_clean_alpha.json \
              examples/labeled/lab_clean_beta.json \
      --holdout examples/labeled/lab_holdout_gamma.json \
                examples/labeled/lab_holdout_delta.json \
      --output results/stage10/labeled
