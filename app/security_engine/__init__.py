"""
Security Engine — ETag Privacy Analyzer
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Performs a REAL, live HTTP GET request to a target URL you provide and
inspects the actual response headers returned by that server. Nothing is
simulated: if the target is unreachable, that is reported as a real error,
not silently faked.

SAFETY: This engine only ever issues a single, standard, non-destructive
GET request per scan. It does not send exploit payloads, brute-force
anything, or make repeated/high-volume requests.
"""
import time
import requests

DEFAULT_TIMEOUT = 10
DEFAULT_USER_AGENT = "EtagPrivacyAnalyzer/1.0 (+https://github.com/mrshrivasta; educational security tool)"


class ScanEngine:
    def __init__(self, target_url, timeout=DEFAULT_TIMEOUT, verify_tls=True):
        self.target_url = target_url
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.errors_count = 0

    def _fetch(self):
        headers = {"User-Agent": DEFAULT_USER_AGENT}
        resp = requests.get(
            self.target_url, headers=headers, timeout=self.timeout,
            verify=self.verify_tls, allow_redirects=True,
        )
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        return {
            "url": resp.url,
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "headers_lower": headers_lower,
            "elapsed_ms": round(resp.elapsed.total_seconds() * 1000, 1),
        }

    def run(self):
        from app.detection_rules import ALL_RULES
        start = time.time()
        findings = []
        response = None
        try:
            response = self._fetch()
            for rule in ALL_RULES:
                try:
                    result = rule(response)
                except Exception:
                    self.errors_count += 1
                    continue
                if result:
                    result["file_path"] = response["url"]
                    result["permissions_octal"] = str(response["status_code"])
                    result["owner_uid"] = None
                    result["owner_gid"] = None
                    findings.append(result)
        except requests.exceptions.RequestException as exc:
            self.errors_count += 1
            findings.append({
                "rule_id": "EPA-000",
                "rule_name": "Target Unreachable",
                "severity": "low",
                "description": f"Could not reach {self.target_url}: {exc}",
                "file_path": self.target_url,
                "permissions_octal": "-",
                "owner_uid": None,
                "owner_gid": None,
            })

        elapsed = time.time() - start
        return {
            "files_scanned": 1 if response else 0,
            "dirs_scanned": len(response["headers"]) if response else 0,
            "errors_count": self.errors_count,
            "response": response,
            "findings": findings,
            "elapsed_seconds": round(elapsed, 3),
        }
