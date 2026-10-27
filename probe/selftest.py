#!/usr/bin/env python3
"""Offline self-test for tsa_probe.py (no external network).

Builds a throw-away local PKI (root CA -> intermediate CA -> TSA signer) with openssl,
serves a local RFC 3161 TSA, OCSP responder, CA certificates and CRLs on 127.0.0.1,
and runs tsa_probe.py p1 / p3 / p4 / summary against it with a temporary config.
Nothing here contacts a real TSA and nothing is written to probe/tsa/.
"""

import datetime as dt
import http.server
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
PROBE = os.path.join(HERE, "tsa_probe.py")


def sh(args, cwd, inp=None):
    r = subprocess.run(args, cwd=cwd, input=inp, capture_output=True)
    if r.returncode != 0:
        raise SystemExit("command failed: %s\n%s" % (" ".join(args), r.stderr.decode()))
    return r.stdout


OPENSSL_CNF = """
[ req ]
distinguished_name = dn
prompt = no
[ dn ]
CN = placeholder
[ v3_root ]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[ v3_inter ]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
authorityInfoAccess = OCSP;URI:{base}/ocsp-root, caIssuers;URI:{base}/ca/root.der
crlDistributionPoints = URI:{base}/crl/root.crl
[ v3_tsa ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, timeStamping
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
authorityInfoAccess = OCSP;URI:{base}/ocsp-inter, caIssuers;URI:{base}/ca/inter.der
crlDistributionPoints = URI:{base}/crl/inter.crl
[ v3_ocsp ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, OCSPSigning
[ ca_root ]
database = {d}/root_index.txt
crlnumber = {d}/root_crlnumber
default_md = sha256
default_crl_days = 7
[ ca_inter ]
database = {d}/inter_index.txt
crlnumber = {d}/inter_crlnumber
default_md = sha256
default_crl_days = 7
[ tsa ]
default_tsa = tsa_config
[ tsa_config ]
serial = {d}/tsaserial
signer_cert = {d}/tsa.pem
certs = {d}/inter.pem
signer_key = {d}/tsa.key
signer_digest = sha256
default_policy = 1.2.3.4.1
digests = sha256, sha384, sha512
accuracy = secs:1
ordering = no
tsa_name = no
ess_cert_id_chain = no
ess_cert_id_alg = sha256
[ tsa_badacc ]
serial = {d}/tsaserial
signer_cert = {d}/tsa.pem
certs = {d}/inter.pem
signer_key = {d}/tsa.key
signer_digest = sha256
default_policy = 1.2.3.4.2
digests = sha256
accuracy = secs:2
ordering = no
tsa_name = no
ess_cert_id_alg = sha256
"""


def build_pki(d, base):
    cnf = os.path.join(d, "openssl.cnf")
    open(cnf, "w").write(OPENSSL_CNF.format(base=base, d=d))
    for f in ("root_index.txt", "inter_index.txt"):
        open(os.path.join(d, f), "w").close()
    for f in ("root_crlnumber", "inter_crlnumber"):
        open(os.path.join(d, f), "w").write("01\n")
    open(os.path.join(d, "tsaserial"), "w").write("01\n")
    sh(["openssl", "req", "-x509", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", "root.key", "-out", "root.pem",
        "-days", "30", "-subj", "/CN=Selftest Root", "-config", cnf, "-extensions", "v3_root"], d)
    for name, cn, ext, ca, cakey in (("inter", "Selftest Intermediate", "v3_inter", "root", "root"),
                                     ("tsa", "Selftest TSA", "v3_tsa", "inter", "inter"),
                                     ("ocsp", "Selftest OCSP", "v3_ocsp", "inter", "inter")):
        sh(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", name + ".key", "-out", name + ".csr",
            "-subj", "/CN=" + cn, "-config", cnf], d)
        sh(["openssl", "x509", "-req", "-in", name + ".csr", "-CA", ca + ".pem", "-CAkey", cakey + ".key",
            "-CAcreateserial", "-out", name + ".pem", "-days", "20", "-sha256", "-extfile", cnf, "-extensions", ext], d)
    # index entries so OCSP answers "good"
    for name, idx, ca in (("tsa", "inter_index.txt", "inter"), ("inter", "root_index.txt", "root")):
        serial = sh(["openssl", "x509", "-in", name + ".pem", "-noout", "-serial"], d).decode().strip().split("=")[1]
        subj = sh(["openssl", "x509", "-in", name + ".pem", "-noout", "-subject", "-nameopt", "compat"], d).decode().strip()
        subj = subj.split("=", 1)[1].strip()
        end = sh(["openssl", "x509", "-in", name + ".pem", "-noout", "-enddate"], d).decode().strip().split("=")[1]
        endt = dt.datetime.strptime(end, "%b %d %H:%M:%S %Y %Z").strftime("%y%m%d%H%M%SZ")
        open(os.path.join(d, idx), "a").write("V\t%s\t\t%s\tunknown\t%s\n" % (endt, serial, subj))
    for name in ("root", "inter"):
        sh(["openssl", "x509", "-in", name + ".pem", "-outform", "DER", "-out", name + ".der"], d)
        sh(["openssl", "ca", "-gencrl", "-config", cnf, "-name", "ca_" + name, "-cert", name + ".pem",
            "-keyfile", name + ".key", "-out", name + ".crl.pem"], d)
        sh(["openssl", "crl", "-in", name + ".crl.pem", "-outform", "DER", "-out", name + ".crl"], d)
    return cnf


def serve(d, holder):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, body, ctype):
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "max-age=60")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            m = {"/ca/root.der": "root.der", "/ca/inter.der": "inter.der", "/crl/root.crl": "root.crl",
                 "/crl/inter.crl": "inter.crl"}
            if self.path in m:
                self._send(open(os.path.join(d, m[self.path]), "rb").read(), "application/octet-stream")
            else:
                self.send_error(404)

        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            with tempfile.TemporaryDirectory() as td:
                q = os.path.join(td, "q"); r = os.path.join(td, "r")
                open(q, "wb").write(body)
                if self.path in ("/tsa", "/tsa-badacc"):
                    sec = "tsa_config" if self.path == "/tsa" else "tsa_badacc"
                    sh(["openssl", "ts", "-reply", "-config", holder["cnf"], "-section", sec, "-queryfile", q,
                        "-out", r], d)
                    self._send(open(r, "rb").read(), "application/timestamp-reply")
                elif self.path == "/tsa-503":
                    holder["n503"] = holder.get("n503", 0) + 1
                    self.send_error(503)
                elif self.path.startswith("/tsa-status-"):
                    st = int(self.path.rsplit("-", 1)[1])
                    holder.setdefault("nstatus", {})
                    holder["nstatus"][st] = holder["nstatus"].get(st, 0) + 1
                    # TimeStampResp ::= SEQUENCE { status PKIStatusInfo }  (no token)
                    self._send(bytes([0x30, 0x05, 0x30, 0x03, 0x02, 0x01, st]), "application/timestamp-reply")
                elif self.path in ("/ocsp-inter", "/ocsp-root"):
                    ca, idx = ("inter", "inter_index.txt") if self.path == "/ocsp-inter" else ("root", "root_index.txt")
                    signer, key = ("ocsp", "ocsp") if ca == "inter" else ("root", "root")
                    sh(["openssl", "ocsp", "-index", idx, "-CA", ca + ".pem", "-rsigner", signer + ".pem",
                        "-rkey", key + ".key", "-reqin", q, "-respout", r, "-ndays", "1"], d)
                    self._send(open(r, "rb").read(), "application/ocsp-response")
                else:
                    self.send_error(404)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def main():
    work = tempfile.mkdtemp(prefix="tsa-probe-selftest-")
    try:
        pki = os.path.join(work, "pki"); os.makedirs(pki)
        holder = {}
        srv = serve(pki, holder)
        base = "http://127.0.0.1:%d" % srv.server_address[1]
        holder["cnf"] = build_pki(pki, base)
        now = dt.datetime.now(dt.timezone.utc)
        cfg = json.load(open(os.path.join(HERE, "tsa_probe_config.json")))
        cfg.update(stations=[{"id": "LOCAL", "url": base + "/tsa"}, {"id": "BADACC", "url": base + "/tsa-badacc"},
                             {"id": "STOP503", "url": base + "/tsa-503"}] +
                            [{"id": "STATUS%d" % k, "url": base + "/tsa-status-%d" % k} for k in (2, 3, 4, 5)], p1_min_spacing_seconds=1,
                   p3_refetch_wait_seconds=2, p3_slot_minute_utc=now.minute, p3_slot_count=2,
                   p3_first_slot_utc=now.replace(second=0, microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"))
        cfgp = os.path.join(work, "cfg.json"); json.dump(cfg, open(cfgp, "w"))
        out = os.path.join(work, "out")
        env = dict(os.environ, TSA_PROBE_CONFIG=cfgp, no_proxy="127.0.0.1", NO_PROXY="127.0.0.1",
                   http_proxy="", HTTP_PROXY="", https_proxy="", HTTPS_PROXY="")
        for mode, extra in (("p1", []), ("p1", []), ("p3", []), ("p3", []), ("p4", []),
                            ("summary", ["--date", "selftest"])):
            r = subprocess.run([sys.executable, PROBE, mode, "--out-root", out, "--run-id", "t%s" % mode] + extra,
                               env=env, capture_output=True)
            print("$", mode, "rc=%d" % r.returncode, r.stdout.decode().strip()[-200:], r.stderr.decode()[-2000:])
            if r.returncode != 0:
                raise SystemExit(1)
        summ = json.load(open(os.path.join(out, "SUMMARY-selftest.json")))
        st = summ["stations"]["LOCAL"]
        print(json.dumps({"checks": st["checks_over_p1_tokens"], "policy": st["policy_discovery"],
                          "fresh_signer_ocsp": {k: v for k, v in st["freshness"]["signer_ocsp"].items()
                                                if k.startswith("fresh")},
                          "fresh_signer_crl_fetch1": st["freshness"]["signer_crl"]["fresh_vs_same_token_fetch1"],
                          "p3_slots": summ["p3_slots"], "reach": st["reachability_path_A"]}, indent=1))
        res = st["checks_over_p1_tokens"]["result"]
        assert st["checks_over_p1_tokens"]["n_tokens"] == 5, "expected 5 P1 tokens"
        assert all(v == "PASS_IN_PROBE" for v in res.values()), res
        assert st["freshness"]["signer_ocsp"]["fresh_vs_same_token_fetch1"]["verdict"] == "NO_STALE_OBSERVED_IN_PROBE"
        assert st["freshness"]["signer_crl"]["fresh_vs_same_token_fetch1"]["verdict"] == "STALE_OBSERVED_IN_PROBE"
        assert summ["p3_slots"]["with_run"] == 1
        bad = summ["stations"]["BADACC"]["checks_over_p1_tokens"]["result"]
        assert bad["6_accuracy_le_1s"] == "FAIL", bad
        assert summ["stations"]["BADACC"]["policy_discovery"] == ["1.2.3.4.2"]
        # 503 => station stopped after the first request in each run: P1 once + P3 once = 2 requests, no retry
        assert holder.get("n503") == 2, holder.get("n503")
        assert summ["stations"]["STOP503"]["checks_over_p1_tokens"]["n_tokens"] == 0
        # any non-success PKIStatus (2 rejection, 3 waiting, 4 revocationWarning, 5 revocationNotification)
        # => no retry, station stopped: P1 once + P3 once = 2 requests per station
        assert holder.get("nstatus") == {2: 2, 3: 2, 4: 2, 5: 2}, holder.get("nstatus")
        for k in (2, 3, 4, 5):
            logs = []
            for dp, _, names in os.walk(out):
                if os.path.basename(dp) == "STATUS%d" % k and "station_log.json" in names:
                    logs.append(json.load(open(os.path.join(dp, "station_log.json"))))
            assert len(logs) == 2 and all(l["stopped"] == "stop_tsa_rejection_status_%d" % k and
                                          l["tsa_requests"] == 1 for l in logs), logs
        print("SELFTEST PASS")
    finally:
        if not os.environ.get("SELFTEST_KEEP"):
            shutil.rmtree(work, ignore_errors=True)
        else:
            print("kept", work)


if __name__ == "__main__":
    main()
