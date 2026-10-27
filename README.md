# M1-MACRO-PIPELINE-V2

Operational pipeline implementation repository for M1-MACRO-V1.

## Scope

This repository implements M1-MACRO-PIPELINE-V2.

The statistical model, features, estimation method, and evaluation rules of M1-MACRO-V1 are unchanged.

V2 changes only:
- acquisition
- trigger redundancy
- provenance verification
- issuance orchestration
- monitoring and audit

## Isolation

- M1-MACRO-V1 remains frozen and unchanged.
- V1 Forward evidence is not replaced by V2.
- V2 maintains its own Forward series.
- Development Replay is not started by this repository.
- Historical Reserve Holdout remains SEALED.
- Holdout pair-specific calculations, features, forecasts, and market-data access are prohibited.

## Status

V2 implementation repository initialized.

Implementation and acceptance testing are not yet complete.
