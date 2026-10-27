#!/usr/bin/env python3
"""M1-MACRO-PIPELINE-V2 TSA pre-selection probe (PROBE / NON-FORMAL / PRE-SELECTION).

Implements M1-MACRO-PIPELINE-V2-TSA-PROBE-SPEC-V0.1 (frozen; SHA-256 a3e4e447...).
Not Calibration, not Acceptance. Never reads V1 data, M1 code/features/ledgers or
Holdout data. Only measures RFC 3161 tokens, certificate chains, OCSP/CRL and timing.

Dependencies: Python standard library and the `openssl` command line tool only.

Modes:
  p1       P1 + P2 (5 tokens per station, chain, one revocation fetch)   [spec 5.2, 5.3]
  p3       one hourly P3 run (token, fetch1, wait, fetch2)              [spec 5.4]
  p4       offline re-verification of all saved runs (no network)        [spec 5.5]
  summary  pure aggregation of saved files into SUMMARY-<date>.json     [spec 6, 7]
"""

import argparse
import datetime as dt
import decimal
import hashlib
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

D = decimal.Decimal
decimal.getcontext().prec = 40

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.environ.get("TSA_PROBE_CONFIG") or os.path.join(HERE, "tsa_probe_config.json")
OUT_ROOT_DEFAULT = os.path.join(os.path.dirname(HERE), "probe", "tsa")

OID = {
    "sha1": "1.3.14.3.2.26",
    "sha256": "2.16.840.1.101.3.4.2.1",
    "sha384": "2.16.840.1.101.3.4.2.2",
    "sha512": "2.16.840.1.101.3.4.2.3",
    "rsaEncryption": "1.2.840.113549.1.1.1",
    "sha256WithRSA": "1.2.840.113549.1.1.11",
    "sha384WithRSA": "1.2.840.113549.1.1.12",
    "sha512WithRSA": "1.2.840.113549.1.1.13",
    "rsassaPss": "1.2.840.113549.1.1.10",
    "ecdsaSha256": "1.2.840.10045.4.3.2",
    "ecdsaSha384": "1.2.840.10045.4.3.3",
    "ecdsaSha512": "1.2.840.10045.4.3.4",
    "signedData": "1.2.840.113549.1.7.2",
    "tstInfo": "1.2.840.113549.1.9.16.1.4",
    "signingCertificate": "1.2.840.113549.1.9.16.2.12",
    "signingCertificateV2": "1.2.840.113549.1.9.16.2.47",
    "eku": "2.5.29.37",
    "timeStamping": "1.3.6.1.5.5.7.3.8",
    "aia": "1.3.6.1.5.5.7.1.1",
    "ocsp": "1.3.6.1.5.5.7.48.1",
    "caIssuers": "1.3.6.1.5.5.7.48.2",
    "cdp": "2.5.29.31",
    "ski": "2.5.29.14",
    "crlNumber": "2.5.29.20",
    "ocspBasic": "1.3.6.1.5.5.7.48.1.1",
}
SHA2_DIGESTS = {OID["sha256"], OID["sha384"], OID["sha512"]}
SIG_OK = {OID["rsaEncryption"], OID["sha256WithRSA"], OID["sha384WithRSA"], OID["sha512WithRSA"],
          OID["rsassaPss"], OID["ecdsaSha256"], OID["ecdsaSha384"], OID["ecdsaSha512"]}


# ---------------------------------------------------------------- DER (stdlib)

class Node:
    __slots__ = ("cls", "constructed", "tag", "raw", "content", "children")

    def __init__(self, cls, constructed, tag, raw, content):
        self.cls, self.constructed, self.tag, self.raw, self.content = cls, constructed, tag, raw, content
        self.children = parse_all(content) if constructed else None

    def is_univ(self, tag):
        return self.cls == 0 and self.tag == tag

    def is_ctx(self, tag):
        return self.cls == 2 and self.tag == tag


def parse_one(b, i=0):
    start = i
    t = b[i]; i += 1
    cls, constructed, tag = t >> 6, bool(t & 0x20), t & 0x1F
    if tag == 0x1F:
        tag = 0
        while True:
            x = b[i]; i += 1
            tag = (tag << 7) | (x & 0x7F)
            if not x & 0x80:
                break
    ln = b[i]; i += 1
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0:
            raise ValueError("indefinite length not allowed in DER")
        ln = int.from_bytes(b[i:i + n], "big"); i += n
    end = i + ln
    if end > len(b):
        raise ValueError("truncated DER")
    return Node(cls, constructed, tag, b[start:end], b[i:end]), end


def parse_all(b):
    out, i = [], 0
    while i < len(b):
        n, i = parse_one(b, i)
        out.append(n)
    return out


def der(b):
    n, end = parse_one(b, 0)
    if end != len(b):
        raise ValueError("trailing bytes after DER object")
    return n


def oid_str(node):
    c = node.content
    first = c[0]
    parts = [str(min(first // 40, 2)), str(first - 40 * min(first // 40, 2))]
    v = 0
    for x in c[1:]:
        v = (v << 7) | (x & 0x7F)
        if not x & 0x80:
            parts.append(str(v)); v = 0
    return ".".join(parts)


def int_val(node):
    return int.from_bytes(node.content, "big", signed=True)


def text_val(node):
    return node.content.decode("utf-8", "replace")


def enc_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def enc(tag, content):
    return bytes([tag]) + enc_len(len(content)) + content


def enc_int(v):
    b = v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big", signed=True)
    return enc(0x02, b)


def enc_oid(s):
    p = [int(x) for x in s.split(".")]
    out = bytearray([40 * p[0] + p[1]])
    for v in p[2:]:
        chunk = [v & 0x7F]; v >>= 7
        while v:
            chunk.append(0x80 | (v & 0x7F)); v >>= 7
        out += bytes(reversed(chunk))
    return enc(0x06, bytes(out))


def seq(*items):
    return enc(0x30, b"".join(items))


# ---------------------------------------------------------------- time

def now_utc():
    return dt.datetime.now(dt.timezone.utc)


def iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def iso_to_epoch(s):
    """'YYYY-MM-DDTHH:MM:SS.ffffffZ' -> Decimal epoch seconds (exact)."""
    base = dt.datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=dt.timezone.utc)
    frac = s[19:-1]
    return D(int(base.timestamp())) + (D("0" + frac) if frac else D(0))


def asn1_time_epoch(raw):
    """GeneralizedTime 'YYYYMMDDHHMMSS[.f*]Z' or UTCTime 'YYMMDDHHMMSSZ' -> Decimal epoch (exact)."""
    if not raw.endswith("Z"):
        raise ValueError("time not in UTC (Z): " + raw)
    body = raw[:-1]
    if len(body) >= 14 and body[:14].isdigit() and (len(body) == 14 or body[14] in ".,"):
        base, frac = body[:14], body[15:]
        fmt = "%Y%m%d%H%M%S"
    elif len(body) == 12 and body.isdigit():
        yy = int(body[:2])
        base, frac = ("19" if yy >= 50 else "20") + body, ""
        fmt = "%Y%m%d%H%M%S"
    else:
        raise ValueError("unsupported time format: " + raw)
    t = dt.datetime.strptime(base, fmt).replace(tzinfo=dt.timezone.utc)
    return D(int(t.timestamp())) + (D("0." + frac) if frac else D(0))


# ---------------------------------------------------------------- files

def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def sha256_file(p):
    with open(p, "rb") as f:
        return sha256_bytes(f.read())


def write_bytes(p, b):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "wb") as f:
        f.write(b)


def write_json(p, obj):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write("\n")


def read_json(p):
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def load_config():
    return read_json(CONFIG_PATH)


def openssl(args, stdin=None):
    r = subprocess.run(["openssl"] + args, input=stdin, capture_output=True)
    return r.returncode, r.stdout, r.stderr


def pem(der_bytes, label="CERTIFICATE"):
    import base64
    b = base64.encodebytes(der_bytes).decode().replace("\n", "")
    lines = [b[i:i + 64] for i in range(0, len(b), 64)]
    return ("-----BEGIN %s-----\n%s\n-----END %s-----\n" % (label, "\n".join(lines), label)).encode()


# ---------------------------------------------------------------- HTTP

def http(url, body=None, content_type=None, timeout=30):
    """One HTTP exchange. Returns dict with times, status, headers, body (bytes) or error."""
    req = urllib.request.Request(url, data=body, method="POST" if body is not None else "GET")
    if content_type:
        req.add_header("Content-Type", content_type)
    req.add_header("User-Agent", "m1-macro-pipeline-v2-tsa-probe/1 (non-formal pre-selection probe)")
    out = {"url": url, "method": req.get_method()}
    t_send = now_utc()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = r.read()
            t_recv = now_utc()
            out.update(status=r.status, headers=[[k, v] for k, v in r.getheaders()], error=None)
    except urllib.error.HTTPError as e:
        data = e.read() if hasattr(e, "read") else b""
        t_recv = now_utc()
        out.update(status=e.code, headers=[[k, v] for k, v in (e.headers.items() if e.headers else [])],
                   error="HTTPError")
    except Exception as e:  # timeout, DNS, connection
        data = b""
        t_recv = now_utc()
        out.update(status=None, headers=[], error="%s: %s" % (type(e).__name__, e))
    out.update(send_at=iso(t_send), recv_at=iso(t_recv),
               rtt_seconds=str(iso_to_epoch(iso(t_recv)) - iso_to_epoch(iso(t_send))),
               body_sha256=sha256_bytes(data), body_length=len(data))
    return out, data


# ---------------------------------------------------------------- RFC 3161

def make_tsq(imprint):
    nonce = 0
    while nonce == 0:
        nonce = secrets.randbits(64)
    alg = seq(enc_oid(OID["sha256"]), enc(0x05, b""))
    tsq = seq(enc_int(1), seq(alg, enc(0x04, imprint)), enc_int(nonce), enc(0x01, b"\xff"))
    return tsq, nonce


def parse_tsq(b):
    n = der(b)
    ch = n.children
    mi = ch[1].children
    out = {"version": int_val(ch[0]), "imprint_alg": oid_str(mi[0].children[0]),
           "imprint_hex": mi[1].content.hex(), "req_policy": None, "nonce": None, "cert_req": False}
    for c in ch[2:]:
        if c.is_univ(6):
            out["req_policy"] = oid_str(c)
        elif c.is_univ(2):
            out["nonce"] = str(int_val(c))
        elif c.is_univ(1):
            out["cert_req"] = c.content != b"\x00"
    return out


def parse_cert(b):
    n = der(b)
    tbs = n.children[0].children
    i = 0
    version = 1
    if tbs[0].is_ctx(0):
        version = int_val(tbs[0].children[0]) + 1
        i = 1
    serial = int_val(tbs[i])
    issuer_raw, subject_raw = tbs[i + 2].raw, tbs[i + 4].raw
    validity = tbs[i + 3].children
    info = {"version": version, "serial": str(serial), "serial_hex": format(serial, "x"),
            "issuer_der_sha256": sha256_bytes(issuer_raw), "subject_der_sha256": sha256_bytes(subject_raw),
            "self_issued": issuer_raw == subject_raw,
            "not_before": text_val(validity[0]), "not_after": text_val(validity[1]),
            "sha256_fingerprint": sha256_bytes(b), "sha1_fingerprint": hashlib.sha1(b).hexdigest(),
            "eku": None, "eku_critical": None, "ocsp_urls": [], "ca_issuers_urls": [], "crl_urls": [],
            "ski_hex": None}
    exts = [c for c in tbs if c.is_ctx(3)]
    if exts:
        for e in exts[0].children[0].children:
            parts = e.children
            eoid = oid_str(parts[0])
            critical = len(parts) == 3 and parts[1].content != b"\x00"
            val = der(parts[-1].content)
            if eoid == OID["eku"]:
                info["eku"] = [oid_str(x) for x in val.children]
                info["eku_critical"] = critical
            elif eoid == OID["aia"]:
                for ad in val.children:
                    m = oid_str(ad.children[0]); loc = ad.children[1]
                    if loc.is_ctx(6):
                        (info["ocsp_urls"] if m == OID["ocsp"] else
                         info["ca_issuers_urls"] if m == OID["caIssuers"] else []).append(text_val(loc))
            elif eoid == OID["cdp"]:
                for dp in val.children:
                    for part in dp.children:
                        if part.is_ctx(0):
                            for full in part.children:
                                if full.is_ctx(0):
                                    for gn in full.children:
                                        if gn.is_ctx(6):
                                            info["crl_urls"].append(text_val(gn))
            elif eoid == OID["ski"]:
                info["ski_hex"] = val.content.hex()
    rc, out, _ = openssl(["x509", "-inform", "DER", "-noout", "-subject", "-issuer", "-nameopt", "RFC2253"], b)
    info["subject_issuer_text"] = out.decode("utf-8", "replace").strip() if rc == 0 else None
    return info


def parse_tsr(b):
    """Parse TimeStampResp. Returns dict; raises on malformed input."""
    n = der(b)
    st = n.children[0].children
    res = {"status": int_val(st[0]), "status_string": None, "fail_info_hex": None, "token_der": None}
    for c in st[1:]:
        if c.is_univ(16):
            res["status_string"] = [text_val(x) for x in c.children]
        elif c.is_univ(3):
            res["fail_info_hex"] = c.content.hex()
    if len(n.children) < 2:
        return res
    ci = n.children[1]
    res["token_der"] = ci.raw
    res["content_type"] = oid_str(ci.children[0])
    sd = ci.children[1].children[0].children
    k = 1
    k += 1  # digestAlgorithms
    eci = sd[k].children; k += 1
    res["econtent_type"] = oid_str(eci[0])
    tst_der = eci[1].children[0].content
    certs = []
    if k < len(sd) and sd[k].is_ctx(0):
        certs = [c.raw for c in sd[k].children]; k += 1
    if k < len(sd) and sd[k].is_ctx(1):
        k += 1
    signer_infos = sd[k].children
    res["certificates_der"] = certs
    res["signer_count"] = len(signer_infos)
    si = signer_infos[0].children
    sid = si[1]
    if sid.is_univ(16):
        res["sid"] = {"type": "issuerAndSerialNumber", "serial": str(int_val(sid.children[1])),
                      "issuer_der_sha256": sha256_bytes(sid.children[0].raw)}
    else:
        res["sid"] = {"type": "subjectKeyIdentifier", "ski_hex": sid.content.hex()}
    res["digest_algorithm"] = oid_str(si[2].children[0])
    j = 3
    ess = []
    if si[j].is_ctx(0):
        for attr in si[j].children:
            aoid = oid_str(attr.children[0])
            if aoid in (OID["signingCertificate"], OID["signingCertificateV2"]):
                sc = attr.children[1].children[0]
                for cid in sc.children[0].children:
                    parts = cid.children
                    if aoid == OID["signingCertificate"]:
                        ess.append({"type": "ESSCertID", "hash_alg": OID["sha1"], "hash_hex": parts[0].content.hex()})
                    else:
                        if parts[0].is_univ(16):
                            halg, h = oid_str(parts[0].children[0]), parts[1].content.hex()
                        else:
                            halg, h = OID["sha256"], parts[0].content.hex()
                        ess.append({"type": "ESSCertIDv2", "hash_alg": halg, "hash_hex": h})
        j += 1
    res["ess_cert_ids"] = ess
    res["signature_algorithm"] = oid_str(si[j].children[0])
    # TSTInfo
    t = der(tst_der).children
    tst = {"version": int_val(t[0]), "policy": oid_str(t[1]),
           "imprint_alg": oid_str(t[2].children[0].children[0]), "imprint_hex": t[2].children[1].content.hex(),
           "serial": str(int_val(t[3])), "gen_time_raw": t[4].content.decode("ascii"),
           "accuracy": None, "ordering": False, "nonce": None}
    for c in t[5:]:
        if c.is_univ(16):
            acc = {"seconds": None, "millis": None, "micros": None}
            for a in c.children:
                if a.is_univ(2):
                    acc["seconds"] = int_val(a)
                elif a.is_ctx(0):
                    acc["millis"] = int.from_bytes(a.content, "big")
                elif a.is_ctx(1):
                    acc["micros"] = int.from_bytes(a.content, "big")
            tst["accuracy"] = acc
        elif c.is_univ(1):
            tst["ordering"] = c.content != b"\x00"
        elif c.is_univ(2):
            tst["nonce"] = str(int_val(c))
    res["tst_info"] = tst
    return res


def accuracy_seconds(acc):
    if acc is None:
        return None
    return D(acc["seconds"] or 0) + D(acc["millis"] or 0) / 1000 + D(acc["micros"] or 0) / 1000000


def find_signer(tsr):
    sid = tsr["sid"]
    for c in tsr["certificates_der"]:
        info = parse_cert(c)
        if sid["type"] == "issuerAndSerialNumber":
            if info["serial"] == sid["serial"] and info["issuer_der_sha256"] == sid["issuer_der_sha256"]:
                return c, info
        elif info["ski_hex"] == sid["ski_hex"]:
            return c, info
    return None, None


# ---------------------------------------------------------------- OCSP / CRL

def parse_ocsp(b):
    n = der(b)
    out = {"response_status": int_val(n.children[0]), "produced_at_raw": None, "responses": [],
           "responder_certs_der": []}
    if len(n.children) < 2:
        return out
    rb = n.children[1].children[0].children
    out["response_type"] = oid_str(rb[0])
    basic = der(rb[1].content).children
    tbs = basic[0].children
    i = 1 if tbs[0].is_ctx(0) else 0
    out["produced_at_raw"] = tbs[i + 1].content.decode("ascii")
    for sr in tbs[i + 2].children:
        p = sr.children
        certid = p[0].children
        cs = p[1]
        status = {0: "good", 1: "revoked", 2: "unknown"}.get(cs.tag, "?")
        entry = {"serial": str(int_val(certid[3])), "cert_status": status,
                 "this_update_raw": p[2].content.decode("ascii"), "next_update_raw": None,
                 "revocation_time_raw": None}
        if status == "revoked":
            entry["revocation_time_raw"] = cs.children[0].content.decode("ascii")
        for x in p[3:]:
            if x.is_ctx(0):
                entry["next_update_raw"] = x.children[0].content.decode("ascii")
        out["responses"].append(entry)
    for x in basic[3:]:
        if x.is_ctx(0):
            out["responder_certs_der"] = [c.raw for c in x.children[0].children]
    return out


def parse_crl(b, target_serial=None):
    n = der(b)
    tbs = n.children[0].children
    i = 1 if tbs[0].is_univ(2) else 0
    out = {"issuer_der_sha256": sha256_bytes(tbs[i + 1].raw), "this_update_raw": text_val(tbs[i + 2]),
           "next_update_raw": None, "crl_number": None, "revoked_count": 0, "target_listed": None,
           "target_revocation_date_raw": None}
    k = i + 3
    if k < len(tbs) and tbs[k].is_univ(23) or (k < len(tbs) and tbs[k].is_univ(24)):
        out["next_update_raw"] = text_val(tbs[k]); k += 1
    if k < len(tbs) and tbs[k].is_univ(16):
        revoked = tbs[k].children
        out["revoked_count"] = len(revoked)
        if target_serial is not None:
            out["target_listed"] = False
            for r in revoked:
                if str(int_val(r.children[0])) == str(target_serial):
                    out["target_listed"] = True
                    out["target_revocation_date_raw"] = text_val(r.children[1])
        k += 1
    for x in tbs[k:]:
        if x.is_ctx(0):
            for e in x.children[0].children:
                if oid_str(e.children[0]) == OID["crlNumber"]:
                    out["crl_number"] = str(int_val(der(e.children[-1].content)))
    return out


# ---------------------------------------------------------------- probe actions

class Station:
    def __init__(self, sid, url, cfg, run_dir, log):
        self.id, self.url, self.cfg, self.log = sid, url, cfg, log
        self.dir = os.path.join(run_dir, sid)
        self.stopped = None
        self.tsa_requests = 0

    def event(self, **kw):
        kw["at"] = iso(now_utc()); kw["station"] = self.id
        self.log.append(kw)

    def request_token(self, label, probe_run_id, seqno):
        """One logical token request with at most one retry (spec 5.1). Returns parsed tsr or None."""
        if self.stopped:
            self.event(kind="skipped_after_stop", label=label)
            return None
        imprint = hashlib.sha256(("M1-MACRO-PIPELINE-V2 TSA PROBE %s %s %d" %
                                  (probe_run_id, self.id, seqno)).encode()).digest()
        for attempt in range(1, self.cfg["max_retries"] + 2):
            tsq, nonce = make_tsq(imprint)
            base = os.path.join(self.dir, "%s_%d" % (label, attempt))
            write_bytes(base + ".tsq", tsq)
            meta, body = http(self.url, tsq, "application/timestamp-query", self.cfg["http_timeout_seconds"])
            self.tsa_requests += 1
            meta.update(label=label, attempt=attempt, seqno=seqno, nonce=str(nonce),
                        imprint_hex=imprint.hex(), tsq_sha256=sha256_bytes(tsq))
            if body:
                write_bytes(base + ".tsr", body)
            parsed, reason = None, None
            if meta["status"] in self.cfg["stop_http_statuses"]:
                reason = "stop_http_%s" % meta["status"]
            elif meta["status"] != 200 or not body:
                reason = "failure_http_%s" % meta["status"]
            else:
                try:
                    parsed = parse_tsr(body)
                    if parsed["status"] not in (0, 1):
                        # any PKIStatus other than granted(0)/grantedWithMods(1): stop, no retry (spec 5.1)
                        reason = "stop_tsa_rejection_status_%d" % parsed["status"]
                except Exception as e:
                    reason = "failure_parse: %s" % e
                    parsed = None
            meta["outcome"] = reason or "ok"
            write_json(base + ".http.json", meta)
            if body:
                rc, out, err = openssl(["ts", "-reply", "-in", base + ".tsr", "-text"])
                write_bytes(base + ".tsr.txt", out + (b"\n[stderr]\n" + err if err else b""))
            self.event(kind="tsa_request", label=label, attempt=attempt, outcome=meta["outcome"],
                       http_status=meta["status"], rtt_seconds=meta["rtt_seconds"])
            if reason is None:
                return {"base": base, "parsed": parsed, "meta": meta}
            if reason.startswith("stop_"):
                self.stopped = reason
                self.event(kind="station_stopped", reason=reason)
                return None
            if attempt <= self.cfg["max_retries"]:
                time.sleep(self.cfg["retry_delay_seconds"])
        return None


def fetch_with_retry(cfg, url, body=None, ctype=None):
    last = None
    for attempt in range(1, cfg["max_retries"] + 2):
        meta, data = http(url, body, ctype, cfg["http_timeout_seconds"])
        meta["attempt"] = attempt
        if meta["status"] == 200 and data:
            return meta, data
        last = (meta, data)
        if attempt <= cfg["max_retries"]:
            time.sleep(cfg["retry_delay_seconds"])
    return last


def build_chain(cfg, station, signer_der, token_certs, outdir):
    """Signer -> intermediates -> root via token certificates, then AIA caIssuers (spec 5.3)."""
    chain = [signer_der]
    pool = list(token_certs)
    cur = signer_der
    for _ in range(6):
        info = parse_cert(cur)
        if info["self_issued"]:
            break
        cur_issuer_hash = info["issuer_der_sha256"]
        nxt = None
        for c in pool:
            if parse_cert(c)["subject_der_sha256"] == cur_issuer_hash and c not in chain:
                nxt = c
                break
        if nxt is None:
            for u in info["ca_issuers_urls"]:
                res = fetch_with_retry(cfg, u)
                meta, data = res
                name = "aia_%s" % hashlib.sha256(u.encode()).hexdigest()[:12]
                write_json(os.path.join(outdir, name + ".http.json"), meta)
                if data:
                    write_bytes(os.path.join(outdir, name + ".bin"), data)
                    cand = data
                    if data.startswith(b"-----BEGIN"):
                        rc, o, _ = openssl(["x509", "-outform", "DER"], data)
                        cand = o if rc == 0 else b""
                    try:
                        if cand and parse_cert(cand)["subject_der_sha256"] == cur_issuer_hash:
                            nxt = cand
                            break
                    except Exception:
                        # PKCS#7 bundles: try openssl pkcs7 -print_certs
                        rc, o, _ = openssl(["pkcs7", "-inform", "DER", "-print_certs"], data)
                        if rc == 0:
                            for blk in o.split(b"-----END CERTIFICATE-----")[:-1]:
                                rc2, c2, _ = openssl(["x509", "-outform", "DER"], blk + b"-----END CERTIFICATE-----\n")
                                if rc2 == 0 and parse_cert(c2)["subject_der_sha256"] == cur_issuer_hash:
                                    nxt = c2
                                    break
                    if nxt:
                        break
        if nxt is None:
            station.event(kind="chain_incomplete", at_cert=info["sha256_fingerprint"])
            break
        chain.append(nxt)
        cur = nxt
    for idx, c in enumerate(chain):
        write_bytes(os.path.join(outdir, "chain_%d.der" % idx), c)
        write_json(os.path.join(outdir, "chain_%d.json" % idx), parse_cert(c))
    return chain


def in_os_trust_store(root_der):
    with tempfile.NamedTemporaryFile(suffix=".pem") as f:
        f.write(pem(root_der)); f.flush()
        rc2, out2, _ = openssl(["verify", f.name])
    return {"openssl_verify_default_store_rc": rc2, "output": out2.decode("utf-8", "replace").strip()}


def fetch_revocation(cfg, station, chain, outdir, tag):
    """OCSP (AIA) and CRL (CDP) for signer (role 0) and intermediate (role 1) (spec 5.4 steps 2-3)."""
    results = []
    for role, name in ((0, "signer"), (1, "intermediate")):
        if role + 1 >= len(chain):
            results.append({"role": name, "kind": "ocsp", "available": False, "reason": "no_issuer_in_chain"})
            continue
        cert, issuer = chain[role], chain[role + 1]
        info = parse_cert(cert)
        with tempfile.TemporaryDirectory() as td:
            cp, ip = os.path.join(td, "c.pem"), os.path.join(td, "i.pem")
            write_bytes(cp, pem(cert)); write_bytes(ip, pem(issuer))
            for url in info["ocsp_urls"][:1]:
                rq = os.path.join(td, "req.der")
                rc, _, err = openssl(["ocsp", "-issuer", ip, "-cert", cp, "-no_nonce", "-reqout", rq])
                base = os.path.join(outdir, "%s_%s_ocsp" % (tag, name))
                if rc != 0:
                    results.append({"role": name, "kind": "ocsp", "available": True, "url": url,
                                    "error": "request_build_failed: " + err.decode()[:200]})
                    continue
                req = open(rq, "rb").read()
                write_bytes(base + ".req.der", req)
                meta, data = fetch_with_retry(cfg, url, req, "application/ocsp-request")
                write_json(base + ".http.json", meta)
                rec = {"role": name, "kind": "ocsp", "available": True, "url": url, "fetched_at": meta["recv_at"],
                       "http_status": meta["status"], "base": os.path.relpath(base, outdir)}
                if data:
                    write_bytes(base + ".der", data)
                    try:
                        p = parse_ocsp(data)
                        p.pop("responder_certs_der", None)
                        rec["parsed"] = p
                    except Exception as e:
                        rec["parse_error"] = str(e)
                results.append(rec)
            if not info["ocsp_urls"]:
                results.append({"role": name, "kind": "ocsp", "available": False, "reason": "no_ocsp_url"})
            for url in info["crl_urls"][:1]:
                base = os.path.join(outdir, "%s_%s_crl" % (tag, name))
                meta, data = fetch_with_retry(cfg, url)
                write_json(base + ".http.json", meta)
                rec = {"role": name, "kind": "crl", "available": True, "url": url, "fetched_at": meta["recv_at"],
                       "http_status": meta["status"], "base": os.path.relpath(base, outdir)}
                if data:
                    if data.startswith(b"-----BEGIN"):
                        rc, o, _ = openssl(["crl", "-outform", "DER"], data)
                        data = o if rc == 0 else data
                    write_bytes(base + ".der", data)
                    try:
                        rec["parsed"] = parse_crl(data, info["serial"])
                    except Exception as e:
                        rec["parse_error"] = str(e)
                results.append(rec)
            if not info["crl_urls"]:
                results.append({"role": name, "kind": "crl", "available": False, "reason": "no_crl_url"})
    for r in results:
        station.event(kind="revocation_fetch", tag=tag, role=r["role"], type=r["kind"],
                      available=r.get("available"), http_status=r.get("http_status"))
    return results


def tool_versions():
    rc, out, _ = openssl(["version", "-a"])
    return {"openssl": out.decode("utf-8", "replace").strip(), "python": sys.version,
            "image_os": os.environ.get("ImageOS"), "image_version": os.environ.get("ImageVersion"),
            "runner_os": os.environ.get("RUNNER_OS"), "runner_arch": os.environ.get("RUNNER_ARCH")}


def finish_manifest(run_dir, manifest):
    files = []
    for root, _, names in os.walk(run_dir):
        for nme in sorted(names):
            p = os.path.join(root, nme)
            if os.path.basename(p) == "manifest.json":
                continue
            files.append({"path": os.path.relpath(p, run_dir), "sha256": sha256_file(p)})
    manifest["files"] = sorted(files, key=lambda x: x["path"])
    manifest["finished_at"] = iso(now_utc())
    write_json(os.path.join(run_dir, "manifest.json"), manifest)


def base_manifest(cfg, mode, probe_run_id, launch, scheduled):
    return {"schema_version": "TSA_PROBE_RUN_V1", "classification": cfg["classification"],
            "mode": mode, "probe_run_id": probe_run_id, "launch_kind": launch, "scheduled_time_utc": scheduled,
            "started_at": iso(now_utc()), "spec_id": cfg["spec_id"], "spec_sha256": cfg["spec_sha256"],
            "script_sha256": sha256_file(os.path.abspath(__file__)), "config_sha256": sha256_file(CONFIG_PATH),
            "stations": cfg["stations"], "tools": tool_versions(),
            "github": {k: os.environ.get(k) for k in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_SHA",
                                                      "GITHUB_EVENT_NAME", "GITHUB_REPOSITORY")}}


def existing_runs(out_root, mode):
    if not os.path.isdir(out_root):
        return []
    res = []
    for d in sorted(os.listdir(out_root)):
        m = os.path.join(out_root, d, "manifest.json")
        if os.path.isfile(m):
            j = read_json(m)
            if j.get("mode") == mode:
                res.append(j)
    return res


def cmd_p1(args, cfg):
    if existing_runs(args.out_root, "p1"):
        print("P1 already exists; P1 runs only once (spec 5.2). Nothing done.")
        return 0
    rid = "p1-%s" % args.run_id
    run_dir = os.path.join(args.out_root, rid)
    manifest = base_manifest(cfg, "p1", rid, args.launch, None)
    log = []
    stations = [Station(s["id"], s["url"], cfg, run_dir, log) for s in cfg["stations"]]
    tokens = {s.id: [] for s in stations}
    last_req = {}
    for seqno in range(1, cfg["p1_requests_per_station"] + 1):
        for st in stations:
            if st.id in last_req:
                wait = cfg["p1_min_spacing_seconds"] - (time.monotonic() - last_req[st.id])
                if wait > 0:
                    time.sleep(wait)
            last_req[st.id] = time.monotonic()
            r = st.request_token("p1_tok%d" % seqno, rid, seqno)
            if r:
                tokens[st.id].append(r)
    for st in stations:
        if not tokens[st.id]:
            continue
        first = tokens[st.id][0]["parsed"]
        signer, _ = find_signer(first)
        if signer is None:
            st.event(kind="signer_not_found_in_token")
            continue
        cdir = os.path.join(st.dir, "chain")
        chain = build_chain(cfg, st, signer, first["certificates_der"], cdir)
        write_json(os.path.join(cdir, "root_trust_store.json"), in_os_trust_store(chain[-1]))
        rev = fetch_revocation(cfg, st, chain, os.path.join(st.dir, "rev"), "p1")
        write_json(os.path.join(st.dir, "rev", "p1_revocation.json"), rev)
    for st in stations:
        write_json(os.path.join(st.dir, "station_log.json"),
                   {"tsa_requests": st.tsa_requests, "stopped": st.stopped,
                    "events": [e for e in log if e["station"] == st.id]})
    finish_manifest(run_dir, manifest)
    return 0


def p3_slots(cfg):
    if not cfg.get("p3_first_slot_utc"):
        return []
    first = dt.datetime.strptime(cfg["p3_first_slot_utc"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    if first.minute != cfg["p3_slot_minute_utc"] or first.second != 0:
        raise SystemExit("p3_first_slot_utc must be at minute %d" % cfg["p3_slot_minute_utc"])
    return [first + dt.timedelta(hours=h) for h in range(cfg["p3_slot_count"])]


def cmd_p3(args, cfg):
    slots = p3_slots(cfg)
    if not slots:
        print("p3_first_slot_utc not set: P3 disabled. Nothing done.")
        return 0
    start = now_utc()
    past = [s for s in slots if s <= start]
    if not past:
        print("before the first P3 slot. Nothing done.")
        return 0
    slot = past[-1]
    if start - slot >= dt.timedelta(hours=1):
        print("after the last P3 slot window. Nothing done.")
        return 0
    slot_s = slot.strftime("%Y-%m-%dT%H:%M:%SZ")
    if any(r.get("scheduled_time_utc") == slot_s for r in existing_runs(args.out_root, "p3")):
        print("slot %s already has a P3 run; not repeated. Nothing done." % slot_s)
        return 0
    rid = "p3-%s-%s" % (slot.strftime("%Y%m%dT%H%MZ"), args.run_id)
    run_dir = os.path.join(args.out_root, rid)
    manifest = base_manifest(cfg, "p3", rid, args.launch, slot_s)
    manifest["slot_index"] = slots.index(slot)
    log = []
    stations = [Station(s["id"], s["url"], cfg, run_dir, log) for s in cfg["stations"]]
    state = {}
    for st in stations:
        r = st.request_token("p3_tok", rid, 1)
        if not r:
            continue
        signer, _ = find_signer(r["parsed"])
        if signer is None:
            st.event(kind="signer_not_found_in_token")
            continue
        chain = build_chain(cfg, st, signer, r["parsed"]["certificates_der"], os.path.join(st.dir, "chain"))
        rev1 = fetch_revocation(cfg, st, chain, os.path.join(st.dir, "rev"), "fetch1")
        state[st.id] = {"chain": chain, "token": r, "fetch1": rev1}
    if state:
        time.sleep(cfg["p3_refetch_wait_seconds"])
    for st in stations:
        if st.id not in state:
            continue
        s = state[st.id]
        rev2 = fetch_revocation(cfg, st, s["chain"], os.path.join(st.dir, "rev"), "fetch2")
        write_json(os.path.join(st.dir, "rev", "p3_revocation.json"), {"fetch1": s["fetch1"], "fetch2": rev2})
    for st in stations:
        write_json(os.path.join(st.dir, "station_log.json"),
                   {"tsa_requests": st.tsa_requests, "stopped": st.stopped,
                    "events": [e for e in log if e["station"] == st.id]})
    finish_manifest(run_dir, manifest)
    return 0


# ---------------------------------------------------------------- P4 (offline)

def verify_ocsp_sig(resp_der, issuer_der, root_der, td):
    rp, ip, ca = os.path.join(td, "r.der"), os.path.join(td, "i.pem"), os.path.join(td, "ca.pem")
    write_bytes(rp, resp_der); write_bytes(ip, pem(issuer_der)); write_bytes(ca, pem(root_der) + pem(issuer_der))
    rc, out, err = openssl(["ocsp", "-respin", rp, "-issuer", ip, "-CAfile", ca, "-no-CApath", "-resp_text",
                            "-ignore_err"])
    ok = rc == 0 and b"Response verify OK" in err
    return {"verify_ok": ok, "rc": rc, "stderr": err.decode("utf-8", "replace")[-400:]}


def verify_crl_sig(crl_der, issuer_der, root_der, td):
    cp, ca = os.path.join(td, "c.der"), os.path.join(td, "ca.pem")
    write_bytes(cp, crl_der); write_bytes(ca, pem(root_der) + pem(issuer_der))
    rc, out, err = openssl(["crl", "-inform", "DER", "-in", cp, "-CAfile", ca, "-no-CApath", "-noout"])
    ok = rc == 0 and b"verify OK" in err + out
    return {"verify_ok": ok, "rc": rc, "stderr": err.decode("utf-8", "replace")[-400:]}


def cmd_p4(args, cfg):
    """Offline: only files under out_root are read. Run inside a network namespace without network."""
    rid = "p4-%s" % args.run_id
    run_dir = os.path.join(args.out_root, rid)
    manifest = base_manifest(cfg, "p4", rid, args.launch, None)
    manifest["network"] = "expected to run under `unshare -n` (no network)"
    results = []
    for run in existing_runs(args.out_root, "p1") + existing_runs(args.out_root, "p3"):
        rdir = os.path.join(args.out_root, run["probe_run_id"])
        for s in cfg["stations"]:
            sdir = os.path.join(rdir, s["id"])
            cdir = os.path.join(sdir, "chain")
            if not os.path.isdir(cdir):
                continue
            chain = []
            k = 0
            while os.path.isfile(os.path.join(cdir, "chain_%d.der" % k)):
                chain.append(open(os.path.join(cdir, "chain_%d.der" % k), "rb").read()); k += 1
            root = chain[-1]
            with tempfile.TemporaryDirectory() as td:
                ca, un = os.path.join(td, "root.pem"), os.path.join(td, "untrusted.pem")
                write_bytes(ca, pem(root)); write_bytes(un, b"".join(pem(c) for c in chain[:-1]) or pem(root))
                for nme in sorted(os.listdir(sdir)):
                    if not nme.endswith(".tsr"):
                        continue
                    base = os.path.join(sdir, nme[:-4])
                    meta = read_json(base + ".http.json")
                    if meta.get("outcome") != "ok":
                        continue
                    rec = {"run": run["probe_run_id"], "station": s["id"], "file": os.path.relpath(base, args.out_root)}
                    try:
                        p = parse_tsr(open(base + ".tsr", "rb").read())
                        gt = asn1_time_epoch(p["tst_info"]["gen_time_raw"])
                        rc, out, err = openssl(["ts", "-verify", "-digest", meta["imprint_hex"], "-in", base + ".tsr",
                                                "-CAfile", ca, "-untrusted", un,
                                                "-attime", str(int(gt))])
                        rec.update(ts_verify_ok=(rc == 0 and b"Verification: OK" in out),
                                   ts_verify_output=(out + err).decode("utf-8", "replace")[-400:])
                    except Exception as e:
                        rec.update(ts_verify_ok=False, error=str(e))
                    results.append(rec)
                rdir_rev = os.path.join(sdir, "rev")
                if os.path.isdir(rdir_rev):
                    for nme in sorted(os.listdir(rdir_rev)):
                        if not nme.endswith(".der") or nme.endswith(".req.der"):
                            continue
                        role = 0 if "_signer_" in nme else 1
                        if role + 1 >= len(chain):
                            continue
                        data = open(os.path.join(rdir_rev, nme), "rb").read()
                        fn = verify_ocsp_sig if "_ocsp" in nme else verify_crl_sig
                        r = fn(data, chain[role + 1], root, td)
                        r.update(run=run["probe_run_id"], station=s["id"], file=os.path.join(
                            os.path.relpath(rdir_rev, args.out_root), nme))
                        results.append(r)
    write_json(os.path.join(run_dir, "p4_results.json"), results)
    finish_manifest(run_dir, manifest)
    return 0


# ---------------------------------------------------------------- summary (pure)

def check_token(tok_base, station_dir, rev_records):
    """Part 2 §6.2 checks applied mechanically (spec 6.1). Returns dict check -> bool/None."""
    meta = read_json(tok_base + ".http.json")
    tsq = parse_tsq(open(tok_base + ".tsq", "rb").read())
    p = parse_tsr(open(tok_base + ".tsr", "rb").read())
    t = p.get("tst_info") or {}
    c = {}
    c["1_status"] = p["status"] == 0 or (p["status"] == 1 and bool(p["status_string"]))
    c["2_request_imprint_nonce_certreq"] = (tsq["imprint_alg"] == OID["sha256"] and tsq["imprint_hex"] == meta["imprint_hex"]
                                            and tsq["nonce"] == meta["nonce"] and tsq["cert_req"] and tsq["req_policy"] is None)
    if not t:
        return c, None, p
    c["3_imprint"] = t["imprint_alg"] == OID["sha256"] and t["imprint_hex"] == meta["imprint_hex"]
    c["4_nonce"] = t["nonce"] == meta["nonce"]
    acc = accuracy_seconds(t["accuracy"])
    c["6_accuracy_le_1s"] = acc is not None and acc <= 1
    try:
        asn1_time_epoch(t["gen_time_raw"]); c["7_gentime_utc"] = len(t["gen_time_raw"]) >= 15
    except Exception:
        c["7_gentime_utc"] = False
    c["8a_signature_alg"] = p["digest_algorithm"] in SHA2_DIGESTS and p["signature_algorithm"] in SIG_OK
    signer, sinfo = find_signer(p)
    ess_ok = False
    if signer is not None:
        for e in p["ess_cert_ids"]:
            h = {OID["sha1"]: hashlib.sha1, OID["sha256"]: hashlib.sha256, OID["sha384"]: hashlib.sha384,
                 OID["sha512"]: hashlib.sha512}.get(e["hash_alg"])
            if h and h(signer).hexdigest() == e["hash_hex"]:
                ess_ok = True
    c["8b_esscertid"] = ess_ok
    c["9_eku_timestamping_only_critical"] = bool(sinfo and sinfo["eku"] == [OID["timeStamping"]] and sinfo["eku_critical"])
    return c, sinfo, p


def summarize_rev(records, role, kind):
    return [r for r in records if r.get("role") == role and r.get("kind") == kind]


def issued_epoch(rec):
    """Issuance time used by Part 2 check 11: OCSP producedAt, CRL thisUpdate."""
    p = rec.get("parsed")
    if not p:
        return None
    raw = p.get("produced_at_raw") if rec["kind"] == "ocsp" else p.get("this_update_raw")
    return asn1_time_epoch(raw) if raw else None


def verdict(passes, total):
    if total == 0:
        return "NOT_OBSERVED"
    return "NO_STALE_OBSERVED_IN_PROBE" if passes == total else "STALE_OBSERVED_IN_PROBE"


def dist(vals):
    if not vals:
        return None
    v = sorted(vals)
    mid = v[len(v) // 2] if len(v) % 2 else (v[len(v) // 2 - 1] + v[len(v) // 2]) / 2
    return {"n": len(v), "min": str(v[0]), "median": str(mid), "max": str(v[-1])}


def cmd_summary(args, cfg):
    root = args.out_root
    p1 = existing_runs(root, "p1")
    p3 = existing_runs(root, "p3")
    p4 = existing_runs(root, "p4")
    p4_results = []
    for r in p4:
        p4_results += read_json(os.path.join(root, r["probe_run_id"], "p4_results.json"))
    out = {"schema_version": "TSA_PROBE_SUMMARY_V1", "classification": cfg["classification"],
           "spec_id": cfg["spec_id"], "spec_sha256": cfg["spec_sha256"],
           "summary_script_sha256": sha256_file(os.path.abspath(__file__)), "config_sha256": sha256_file(CONFIG_PATH),
           "inputs": {"p1": [r["probe_run_id"] for r in p1], "p3": [r["probe_run_id"] for r in p3],
                      "p4": [r["probe_run_id"] for r in p4]},
           "note": "Descriptive probe results only. No pass/fail threshold (spec 6.2). p_min 0.99 is not used. "
                   "R-ACC-12 is N/A (verifier rule); R-ACC-13 is not measured by the probe (spec 8).",
           "stations": {}}
    slots = [s.strftime("%Y-%m-%dT%H:%M:%SZ") for s in p3_slots(cfg)]
    observed_slots = {r["scheduled_time_utc"] for r in p3}
    out["p3_slots"] = {"configured": len(slots), "with_run": len(observed_slots & set(slots)),
                       "not_observed": sorted(set(slots) - observed_slots)}
    for s in cfg["stations"]:
        sid = s["id"]
        S = {"r_acc": {}, "policy_discovery": [], "tokens": [], "freshness": {}, "reachability": {}}
        # ---- 6.1 R-ACC-1..11 from P1 tokens
        checks_all = []
        for run in p1:
            sdir = os.path.join(root, run["probe_run_id"], sid)
            if not os.path.isdir(sdir):
                continue
            rev = []
            rp = os.path.join(sdir, "rev", "p1_revocation.json")
            if os.path.isfile(rp):
                rev = read_json(rp)
            for nme in sorted(os.listdir(sdir)):
                if nme.endswith(".tsr"):
                    base = os.path.join(sdir, nme[:-4])
                    outcome = read_json(base + ".http.json").get("outcome")
                    if outcome != "ok":
                        # an HTTP 200 body that is not a usable TimeStampResp is an R-ACC-1 observation
                        if read_json(base + ".http.json").get("status") == 200:
                            S["tokens"].append({"file": os.path.relpath(base, root), "outcome": outcome})
                            checks_all.append({"1_status": False})
                        continue
                    c, sinfo, p = check_token(base, sdir, rev)
                    rel = os.path.relpath(base, root)
                    pv = [x for x in p4_results if x.get("file") == rel]
                    c["10_chain_verify_offline"] = bool(pv and pv[0].get("ts_verify_ok"))
                    gt = p.get("tst_info", {}).get("gen_time_raw")
                    c["12a_not_revoked_at_gentime"] = None
                    if gt:
                        g = asn1_time_epoch(gt)
                        states = []
                        for r in rev:
                            pr = r.get("parsed")
                            if not pr:
                                continue
                            if r["kind"] == "ocsp":
                                for e in pr["responses"]:
                                    if e["cert_status"] == "revoked":
                                        states.append(asn1_time_epoch(e["revocation_time_raw"]) > g)
                                    else:
                                        states.append(e["cert_status"] == "good")
                            else:
                                if pr.get("target_listed"):
                                    states.append(asn1_time_epoch(pr["target_revocation_date_raw"]) > g)
                                elif pr.get("target_listed") is False:
                                    states.append(True)
                        c["12a_not_revoked_at_gentime"] = (all(states) if states else None)
                    S["policy_discovery"].append(p.get("tst_info", {}).get("policy"))
                    S["tokens"].append({"file": rel, "checks": c,
                                        "gen_time_raw": gt, "accuracy": (p.get("tst_info") or {}).get("accuracy"),
                                        "status": p["status"], "status_string": p["status_string"]})
                    checks_all.append(c)
        keys = sorted({k for c in checks_all for k in c})
        per_check = {}
        for k in keys:
            vals = [c.get(k) for c in checks_all]
            if not vals or all(v is None for v in vals):
                per_check[k] = "NOT_OBSERVED"
            elif any(v is False for v in vals) or any(v is None for v in vals):
                per_check[k] = "FAIL" if any(v is False for v in vals) else "NOT_OBSERVED_FOR_SOME"
            else:
                per_check[k] = "PASS_IN_PROBE"
        S["checks_over_p1_tokens"] = {"n_tokens": len(checks_all), "result": per_check,
                                      "rule": "any failing token -> FAIL (spec 6.1)"}
        S["policy_discovery"] = sorted({x for x in S["policy_discovery"] if x})
        S["r_acc"]["R-ACC-8"] = "POLICY_DISCOVERY_ONLY (no reqPolicy; not a Part 2 policy-check PASS)"
        S["r_acc"]["R-ACC-12"] = "N/A (verifier rule, Part 2 §6.1/§6.2)"
        S["r_acc"]["R-ACC-13"] = "NOT MEASURED (provider written confirmation, spec 8)"
        # ---- 6.2 freshness from P3
        rows = []  # per run: token genTime, fetch1, fetch2 records
        for run in p3:
            sdir = os.path.join(root, run["probe_run_id"], sid)
            rp = os.path.join(sdir, "rev", "p3_revocation.json")
            tokp = None
            for a in (1, 2):
                b = os.path.join(sdir, "p3_tok_%d" % a)
                if os.path.isfile(b + ".tsr") and read_json(b + ".http.json").get("outcome") == "ok":
                    tokp = b + ".tsr"
            g = None
            if tokp:
                try:
                    g = asn1_time_epoch(parse_tsr(open(tokp, "rb").read())["tst_info"]["gen_time_raw"])
                except Exception:
                    g = None
            rv = read_json(rp) if os.path.isfile(rp) else None
            rows.append({"run": run["probe_run_id"], "slot": run["scheduled_time_utc"], "gen": g, "rev": rv})
        gens = [(r["gen"], r["run"]) for r in rows if r["gen"] is not None]
        for role in ("signer", "intermediate"):
            for kind in ("ocsp", "crl"):
                key = "%s_%s" % (role, kind)
                same1 = [0, 0, []]
                same2 = [0, 0, []]
                win = [0, 0, [], []]
                maxwin = [0, 0]
                lags, issued_series, headers = [], [], []
                not_obs = 0
                for r in rows:
                    if r["rev"] is None or r["gen"] is None:
                        not_obs += 1
                        continue
                    for tag, acc in (("fetch1", same1), ("fetch2", same2)):
                        recs = summarize_rev(r["rev"][tag], role, kind)
                        if not recs or issued_epoch(recs[0]) is None:
                            continue
                        e = issued_epoch(recs[0])
                        acc[1] += 1
                        if e >= r["gen"]:
                            acc[0] += 1
                        else:
                            acc[2].append(r["run"])
                        lags.append(iso_to_epoch(recs[0]["fetched_at"]) - e)
                        issued_series.append((recs[0]["fetched_at"], str(e)))
                    recs2 = summarize_rev(r["rev"]["fetch2"], role, kind)
                    if recs2 and issued_epoch(recs2[0]) is not None:
                        f_t = iso_to_epoch(recs2[0]["fetched_at"])
                        e = issued_epoch(recs2[0])
                        in_win = [(gg, rn) for gg, rn in gens if f_t - 6 * 3600 <= gg < f_t]
                        fails = [rn for gg, rn in in_win if not e >= gg]
                        win[0] += len(in_win) - len(fails); win[1] += len(in_win)
                        win[2] += [(r["run"], rn) for rn in fails]
                        win[3].append({"fetch_run": r["run"], "pairs": len(in_win), "pass": len(in_win) - len(fails)})
                        if in_win:
                            maxwin[1] += 1
                            if e >= max(gg for gg, _ in in_win):
                                maxwin[0] += 1
                S["freshness"][key] = {
                    "use": "TSA-F1" if role == "signer" else "TSA-F2 material only",
                    "fresh_vs_same_token_fetch1": {"pass": same1[0], "total": same1[1], "stale_runs": same1[2],
                                                   "verdict": verdict(same1[0], same1[1])},
                    "fresh_vs_same_token_fetch2": {"pass": same2[0], "total": same2[1], "stale_runs": same2[2],
                                                   "verdict": verdict(same2[0], same2[1])},
                    "fresh_vs_window_attempts": {"pass": win[0], "total_pairs": win[1],
                                                 "stale_pairs": win[2], "per_fetch": win[3],
                                                 "verdict": verdict(win[0], win[1])},
                    "max_gentime_window_derived": {"pass": maxwin[0], "total": maxwin[1]},
                    "lag_seconds": dist(lags),
                    "issued_time_series": issued_series,
                    "runs_not_observed": not_obs}
        # ---- 6.3 reachability (P1 + P3)
        reach = {}
        for run in p1 + p3:
            sdir = os.path.join(root, run["probe_run_id"], sid)
            if not os.path.isdir(sdir):
                continue
            for dp, _, names in os.walk(sdir):
                for nme in names:
                    if not nme.endswith(".http.json"):
                        continue
                    m = read_json(os.path.join(dp, nme))
                    kind = ("tsa" if nme.startswith("p1_tok") or nme.startswith("p3_tok") else
                            "ocsp" if "_ocsp" in nme else "crl" if "_crl" in nme else "aia")
                    b = reach.setdefault(kind, {"requests": 0, "http_200": 0, "rtts": []})
                    b["requests"] += 1
                    b["http_200"] += 1 if m.get("status") == 200 else 0
                    if m.get("status") is not None:
                        b["rtts"].append(D(m["rtt_seconds"]))
        for k, b in reach.items():
            rr = b.pop("rtts")
            b["rtt_seconds"] = dist(rr)
            b["rtt_le_2s"] = {"count": sum(1 for x in rr if x <= D(cfg["rtt_reference_seconds"])), "of": len(rr),
                              "note": "reference only (spec 6.3)"}
        S["reachability_path_A"] = reach
        out["stations"][sid] = S
    path = os.path.join(root, "SUMMARY-%s.json" % args.date)
    if os.path.exists(path):
        raise SystemExit("summary file already exists: " + path)
    write_json(path, out)
    print(path)
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["p1", "p3", "p4", "summary"])
    ap.add_argument("--run-id", default=os.environ.get("GITHUB_RUN_ID", "local") + "-" +
                    os.environ.get("GITHUB_RUN_ATTEMPT", "1"))
    ap.add_argument("--launch", default=os.environ.get("GITHUB_EVENT_NAME", "local"))
    ap.add_argument("--out-root", default=OUT_ROOT_DEFAULT)
    ap.add_argument("--date", help="summary date label YYYY-MM-DD (summary mode)")
    args = ap.parse_args()
    cfg = load_config()
    if args.mode == "summary" and not args.date:
        ap.error("--date is required for summary")
    return {"p1": cmd_p1, "p3": cmd_p3, "p4": cmd_p4, "summary": cmd_summary}[args.mode](args, cfg)


if __name__ == "__main__":
    sys.exit(main())
