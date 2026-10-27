# TSA probe — implementation notes (for the implementation audit)

- Classification: **PROBE / NON-FORMAL / PRE-SELECTION**. Not Calibration, not Acceptance.
- Spec: M1-MACRO-PIPELINE-V2-TSA-PROBE-SPEC-V0.1, frozen in `junsato1001-ops/-fx-forward-ledger`
  `preregistration/` (freeze commit b65a8192, SHA-256 a3e4e447…, blob 5a7bf7bc).
- Status at the time of writing: **probe NOT STARTED**. Nothing in this directory has contacted a real TSA.
- Files:
  - `.github/workflows/tsa-probe.yml` — the only workflow.
  - `probe/tsa_probe.py` — the fixed probe script (Python standard library + `openssl` CLI only; no pip packages).
  - `probe/tsa_probe_config.json` — stations and parameters.
  - `probe/selftest.py` — offline self-test against a throw-away local PKI on 127.0.0.1.
  - `probe/tsa/` — results (created by runs only).

## 1. Spec → implementation map

| Spec | Requirement | Where |
|---|---|---|
| §2 | no forecast, no M1 code/features/ledger, no V1 repo, no V1 credential, no Holdout data | script reads only its config and `probe/tsa/`; workflow uses only `github.token` of this repository; no secrets |
| §2 | not in Calibration/Acceptance denominators; tokens not used as anchors | results only under `probe/tsa/`; no `records/`, `ledger*/`, `preregistration/` paths exist in the script |
| §3 | GitHub-hosted runner, fixed image | `runs-on: ubuntu-24.04`; `ImageOS`/`ImageVersion` recorded in every manifest (`tool_versions`) |
| §3 | `GITHUB_TOKEN` `contents: write`, this repository only | workflow `permissions: contents: write`; checkout by plain `git clone` (no third-party action) |
| §3 | C-GMO not probed before contract | not in `stations` |
| §3 | path C not measured | workflow runs only on GitHub-hosted runners (path A) |
| §3 | output under `probe/tsa/<Probe_Run_ID>/` | `cmd_p1`, `cmd_p3`, `cmd_p4`; commit step refuses changes outside `probe/tsa` |
| §3 | OpenSSL version, script SHA-256 | `base_manifest` (`tools.openssl`, `script_sha256`, `config_sha256`) |
| §4 | stations C-DC, C-GS; Sectigo excluded | `tsa_probe_config.json` `stations` |
| §5.1 | TimeStampReq v1, SHA-256, 64-bit OS-random positive nonce, certReq TRUE, **no reqPolicy** | `make_tsq` (`secrets.randbits(64)`, non-zero) |
| §5.1 | imprint = SHA-256("M1-MACRO-PIPELINE-V2 TSA PROBE " + Probe_Run_ID + " " + station + " " + seq) | `Station.request_token` |
| §5.1 | timeout 30 s, one retry after 3 s, nothing more | config `http_timeout_seconds`, `retry_delay_seconds`, `max_retries`; `Station.request_token` |
| §5.1 | runner time before send / after receive, UTC microseconds | `http()` `send_at`, `recv_at` |
| §5.1 | HTTP 429/403/503 or TSA rejection → stop that station for the rest of the run, no retry | `stop_http_statuses`; `reason.startswith("stop_")` → `Station.stopped`; later requests logged as `skipped_after_stop` |
| §5.2 | P1 once, manual dispatch, 5 per station, ≥ 20 s apart | `cmd_p1` refuses if any P1 run exists; `p1_requests_per_station`, `p1_min_spacing_seconds` (monotonic clock, per station) |
| §5.2 | save tsq/tsr DER, HTTP status/headers, `openssl ts -reply -text` | `<label>_<attempt>.tsq/.tsr/.http.json/.tsr.txt` |
| §5.2 | per-token record: status (+statusString/failInfo), policy, accuracy, genTime raw, nonce, imprint, signature alg, ESSCertID(v2), certificates | `parse_tsr` (raw genTime string kept as is) |
| §5.3 | signer EKU (critical, timeStamping only), AIA OCSP/caIssuers, CDP, issuer, serial, validity; intermediates via caIssuers to root; DER + SHA-256 fingerprints | `parse_cert`, `build_chain` (`chain/chain_<k>.der/.json`) |
| §5.3 | root in OS trust store (reference only) | `in_os_trust_store` → `chain/root_trust_store.json` |
| §5.4 | 48 hourly slots at minute 41 UTC, no backfill | `p3_slots`; a run takes the latest slot ≤ start; a slot is used at most once; runs after the last slot + 1 h, or before `p3_first_slot_utc` is set, do nothing |
| §5.4 | token → fetch1 (signer + intermediate, OCSP + CRL) → wait 15 min → fetch2 | `cmd_p3`; `p3_refetch_wait_seconds = 900` |
| §5.4 | per-fetch record incl. Cache-Control/Age/Last-Modified/Expires (all headers kept), DER + SHA-256, OCSP responseStatus/certStatus/producedAt/thisUpdate/nextUpdate/responder certs, CRL thisUpdate/nextUpdate/number/target listed | `fetch_revocation`, `parse_ocsp`, `parse_crl` (responder certs stay inside the saved DER) |
| §5.4 | ≤ 96 TSA requests per station in P3 (+10 in P1 = 106) | one logical request per station per slot, ≤ 1 retry |
| §5.5 | P4 offline re-verification in a separate process without network | workflow runs `p4` under `sudo unshare --net`; `openssl ts -verify -attime <genTime>`, OCSP and CRL signature checks against the saved chain |
| §6.1 | Part 2 §6.2 checks 1–10 and 12(a); check 2 reqPolicy and check 5 not performed; any failing token → FAIL | `check_token` + summary `checks_over_p1_tokens` |
| §6.1 | policy OID = policy discovery only | summary `policy_discovery`, `r_acc["R-ACC-8"]` |
| §6.1 | grantedWithMods accepted only with readable statusString | check `1_status` |
| §6.2 | no pass/fail threshold; p_min 0.99 not used | summary has no threshold; verdicts only |
| §6.2 | issuance time = OCSP producedAt, CRL thisUpdate | `issued_epoch` |
| §6.2 | Fresh_vs_same_token (fetch1, fetch2), Fresh_vs_window_attempts (each token with genTime in [t_fetch2 − 6 h, t_fetch2)), Max_genTime_window (derived), Lag | `cmd_summary` freshness block |
| §6.2 | verdicts NO_STALE_OBSERVED_IN_PROBE / STALE_OBSERVED_IN_PROBE / NOT_OBSERVED; signer = TSA-F1, intermediate = TSA-F2 material only | `verdict`, `freshness.<role>_<kind>.use` |
| §6.2 | missing runs not backfilled, counted as NOT_OBSERVED | summary `p3_slots.not_observed`, `runs_not_observed` |
| §6.3 | path-A reachability: success rate and RTT distribution, RTT ≤ 2.0 s (reference) | summary `reachability_path_A` |
| §7 | per-run `manifest.json` (id, launch kind, scheduled time, start time, image, OpenSSL, script SHA-256, spec SHA-256, stations, file SHA-256 list) | `base_manifest`, `finish_manifest` |
| §7 | final pure aggregation reading saved files only → `probe/tsa/SUMMARY-<date>.json` with script SHA-256 | `cmd_summary` (refuses to overwrite) |

## 2. Implementation choices the spec does not fix (please audit)

1. **OCSP requests are sent without a nonce** (`openssl ocsp -no_nonce`, SHA-1 CertID, HTTP POST). Part 2 does not specify an OCSP nonce; a nonce could make some responders sign on demand and would then not reflect the plain behaviour.
2. **OCSP/CRL fetches use the same timeout/retry rule as TSA requests** (30 s, one retry after 3 s). The stop rule (429/403/503) is applied to TSA requests only, as in §5.1.
3. **Only the first OCSP URL and the first CRL URL** of each certificate are used.
4. **P1 also fetches revocation once** (signer and intermediate, OCSP and CRL) after the five tokens, so that check 12(a) and the P4 signature checks have material. These are not TSA requests.
5. **Stations run in sequence inside a P3 run**; the 15-minute wait starts after the last station's fetch1, so each station waits ≥ 15 minutes.
6. **P3 slot assignment**: a delayed scheduled start is assigned to the latest slot at or before its start time; if that slot already has a run, it does nothing. A slot with no run is NOT_OBSERVED.
7. **The schedule keeps firing hourly after the 48 slots** but does nothing (no request). It can be disabled after P3.
8. **Chain building** uses certificates inside the token first, then AIA caIssuers (DER, PEM or PKCS#7). The top of the chain must be self-issued; otherwise `chain_incomplete` is logged.
9. **Self-test**: `probe/selftest.py` runs before P1 and P4. It uses only 127.0.0.1 and a temporary directory; it never writes `probe/tsa/`.

## 3. How to run (only after the implementation audit PASS)

1. Merge this branch into `main` (the schedule runs only from the default branch; until `p3_first_slot_utc` is set it is a no-op).
2. P1: Actions → tsa-probe → Run workflow → mode `p1` (once).
3. P3: set `p3_first_slot_utc` (e.g. `2026-11-01T00:41:00Z`) in `probe/tsa_probe_config.json` in a separate commit before that time; this fixes the 48 slots.
4. After the last slot: mode `p4`, then mode `summary` with a date.
