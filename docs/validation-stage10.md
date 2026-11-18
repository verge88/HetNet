# HetNet Stage 10 — externally supplied labeled aggregates with source/lineage holdout

## Purpose and scientific scope

This stage provides a **local, privacy-minimizing interface** for evaluating
control-unit and zonal rules on annotated, aggregate-only measurements.
Its four committed demonstration files are **synthetic**, not field data.

The attached dissertation motivates node/zone CU monitoring and zonal
comparison. The present aggregate schema and heldout evaluation protocol
are a new HetNet engineering extension; they do not recreate the thesis's
trained models or claim equivalent results.

Stage 8's unlabeled reference/observed aggregate files contain **no security
ground-truth labels** and are **not** silently treated as labeled examples.
Stage 9's injected synthetic labels are separate from this new user-supplied
format. Nothing here implements actual 3GPP/ITU-T protocol conformance.

## Input and privacy boundaries

The local JSON is <= 1 MiB, has schema_version=1, and **only** the following
top-level fields:

- source_id — anonymous ASCII pseudonym, 3–48 characters
- lineage_id — separately declared anonymous capture-family pseudonym
- provenance — synthetic or supplied_aggregate
- annotation_basis — synthetic_injection for synthetic, or
  expert_review_claimed for supplied_aggregate
- labels — exactly six {node, attack_label} records, one for each monitored
  logical node msc2/sgsn3/mme4/dra/pcscf/amf5, boolean only
- measurements — at most 20,000 aggregate rows, each containing exactly
  {node, interval_index, operation_class, reference_count, reported_count,
  cu_verified_claim, quorum_verified_claim}

Allowed operation_class values: MAP, Diameter, GTPv2-C, SIP, SBI.
The interval_index is **relative** and nonnegative, not an absolute timestamp.
reference_count is a nonnegative aggregate of **20–1,000,000** events;
reported_count is a bounded nonnegative aggregate of 0–1,000,000.
The verification-claim fields are strict booleans. Duplicate
(interval_index,node,operation_class) rows, unexpected payloads/identifiers,
duplicate JSON keys, NaN/Infinity and out-of-range values are rejected.

No IMSI/SUPI/MSISDN, packet contents, IP addresses, subscriber IDs, exact
times or unrestricted metadata fields are accepted. No network sockets,
operator API calls or automatic upload are part of this feature.

**Important privacy note:** the lower bound of 20 *events* does **not** mean
20 unique subscribers or k-anonymity. Real aggregates still require an
organization-approved lawful export, disclosure controls, retention policy
and privacy review before use. Do not commit private measurements or
expert-derived labels to a public GitHub branch or CI.

## Label definition and nonleakage

The attack_label is a **node-level, full-assessment-window annotation**:
true means the node's reported control data were maliciously altered for
the **entire measurement window in that source**. Do not use this version
for intermittent attacks or label a node attacked during only part of
the observation window. Doing so could spuriously count a decision from
an earlier, benign period as an attack detection.

The labels and anonymous source IDs are never accessed by the
aggregate_features() detector. Only approved, bounded measurement
fields are used for feature construction. Labels are read after predictions
have been constructed and are used to compute TP/FP/FN/TN. Training
datasets are required to be all-clean; the train-only threshold fit cannot
use attack-positive source records.

The boolean cu_verified_claim/quorum_verified_claim values are
**ASSERTIONS by the file author**, not HMAC validation: actual signed CU
records and observer keys are not supplied with the aggregate-only schema.
Consequently the baseline is deliberately named **cu_claimed_baseline**,
not the cryptographically verified cu_signed_baseline of Stage 9.
The same distinction applies to declared provenance and expert labels:
the validator does not independently verify them.

## Detector policies

Per (interval,node), aggregate the complete permitted operation-class
counter vectors. A node-epoch is eligible only if every included class
claims CU and observer quorum verified. The normalized residual is:

    sum(abs(reported_count - reference_count)) /
    sum(reference_count)

Per interval the leave-one-out peer contrast is:

    max(0, own_normalized_residual - median(other eligible nodes))

At least two *other* eligible nodes are needed to compute a peer median.
Each node-level classifier requires **two adjacent eligible relative
intervals**. For either zonal rule, take the maximum over the minimum
score of each eligible consecutive pair (a single spike does not suffice).

Three comparison rules:

1. cu_claimed_baseline: two adjacent eligible intervals with positive
   residual in both (strict research-only baseline, not cryptographic CU).
2. zone_absolute: pair score exceeds a clean-only fitted threshold.
3. zone_peer: consecutive leave-one-out contrast exceeds its fitted threshold.

If a node lacks a valid consecutive pair, its decision is ABSTAIN rather
than a fabricated normal value. There is no assumed attack-start timestamp
or tail window in this external-format comparator; the full labeled
assessment window is evaluated.

## Train/test isolation

Train files must be fully normal and cover enough eligible consecutive
intervals. Thresholds are the largest clean training score plus 1e-12.
No test labels or counter values affect training.

Across **all** train and holdout files:
- source_id must be unique;
- lineage_id must be unique, so a declared capture lineage cannot appear
  in both partitions;
- a SHA-256 hash of the canonical measurements must also be unique,
  identifying literal reused captures even under renamed IDs and labels.

These checks detect only straightforward leakage. Different names, lineages
and file hashes do **not** prove absence of overlapping subscribers,
shared physical sensors, duplicate transformed data, shared clocks or
site-level confounding. Source/lineage IDs and review claims are supplied
by the user; independent auditing remains essential.

Aggregate outputs contain only source-level dataset audits, thresholds,
metrics, abstentions and fingerprints — **no source measurement rows,
individual node labels or per-node predictions**.

Selective TP/FP/FN/TN and precision/recall/FPR/F1 apply only to decided
cases. Abstentions are not counted as true negatives. Coverage is reported
separately, as is recall_with_abstentions_as_misses for all attack-positive
nodes. Undefined ratios remain null.

## Reproduce using synthetic fixtures

    python -m pip install -e .
    python -m unittest discover -s tests -v

    python -m hetnet labeled-audit \
      --input examples/labeled/lab_clean_alpha.json

    python -m hetnet labeled-eval \
      --train examples/labeled/lab_clean_alpha.json \
              examples/labeled/lab_clean_beta.json \
      --holdout examples/labeled/lab_holdout_gamma.json \
                examples/labeled/lab_holdout_delta.json \
      --output results/stage10/labeled

The four demo files each contain six nodes observed at six relative
intervals, one coarse operation class per node. Both training sources
are fully clean. Gamma has two attacked nodes and fully available
synthetic observations. Delta has two attacked nodes with deliberately
unavailable verification claims and a different honest-node residual
distortion. All labels apply for each file's *full* assessment window,
not a late attack onset.

This is a small deterministic illustration of schema and scoring, not an
external security benchmark, calibrated operator-grade detector, trained ML
system, physical sensor validation or 3GPP Release 18 conformance test.
