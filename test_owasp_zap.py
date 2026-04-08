"""
Simulation d'attaques OWASP ZAP contre le proxy WAF
=====================================================
Ce script reproduit les payloads utilises par l'active scanner
d'OWASP ZAP (Active Scan Rules) pour tester le WAF.

Sources des payloads :
  - OWASP ZAP SQL Injection scanner (TestSQLInjection.java)
  - OWASP ZAP Path Traversal scanner (TestPathTraversal.java)
  - OWASP ZAP XSS scanner (TestCrossSiteScripting.java)
  - OWASP ZAP Remote OS Command Injection (TestRemoteOSCommandInjection.java)
  - OWASP ZAP Remote File Include (TestRemoteFileInclude.java)

Usage :
  1. Demarrer le WAF : python waf_flask_app.py
  2. Lancer ce script : python test_owasp_zap.py
"""

import sys
import requests

WAF_BASE = "http://127.0.0.1:5000"
PASS = "[PASS]"
FAIL = "[FAIL]"
INFO = "[INFO]"

# ---------------------------------------------------------------------------
# Payloads reels extraits des scanners OWASP ZAP
# Source : https://github.com/zaproxy/zap-extensions/tree/main/addOns/ascanrules
# ---------------------------------------------------------------------------

# SQL Injection payloads (TestSQLInjection.java)
ZAP_SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR '1'='1'/*",
    "' OR 1=1--",
    "' OR 1=1#",
    "') OR ('1'='1",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' UNION SELECT null--",
    "1' UNION SELECT null,null--",
    "1; DROP TABLE users--",
    "1; SELECT * FROM information_schema.tables--",
    "' AND 1=2 UNION SELECT 1,2,3--",
    "admin'--",
    "' OR 'x'='x",
]

# Path Traversal payloads (TestPathTraversal.java)
ZAP_PATH_TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../etc/shadow",
    "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "/etc/passwd",
    "/etc/shadow",
    "/windows/system32/cmd.exe",
    "file:///etc/passwd",
    "../../boot.ini",
]

# XSS payloads (TestCrossSiteScripting.java)
ZAP_XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<body onload=alert(1)>",
    "javascript:alert(1)",
    "<svg onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
]

# OS Command Injection (TestRemoteOSCommandInjection.java)
ZAP_CMDI_PAYLOADS = [
    ";ls",
    ";cat /etc/passwd",
    "|whoami",
    "| dir",
    "`id`",
    "$(id)",
    "&& id",
    "; id",
    "| id #",
    ";ping -c 1 127.0.0.1",
]

# Remote File Include (TestRemoteFileInclude.java)
ZAP_RFI_PAYLOADS = [
    "http://evil.com/shell.txt",
    "https://attacker.com/malware.php",
    "ftp://malicious.ftp/evil.php",
    "http://169.254.169.254/latest/meta-data/",  # AWS metadata
]


def send_to_waf(path, user_agent="Mozilla/5.0 ZAP Active Scanner"):
    """Envoie un payload via /proxy au WAF et retourne le statut."""
    try:
        url = f"{WAF_BASE}/proxy/{path.lstrip('/')}"
        r = requests.get(url, headers={"User-Agent": user_agent},
                         timeout=5, allow_redirects=False)
        return r.status_code
    except requests.exceptions.ConnectionError:
        print(f"\n  WAF inaccessible sur {WAF_BASE}")
        print("  Lancez d'abord : python waf_flask_app.py\n")
        sys.exit(1)


def run_category(name, payloads, base_path="/search?q=", ua="Mozilla/5.0 ZAP Active Scanner"):
    """Execute une categorie de payloads et affiche les resultats."""
    print(f"\n--- {name} ({len(payloads)} payloads) ---")
    blocked = 0
    allowed = 0
    for payload in payloads:
        path = base_path + requests.utils.quote(payload, safe='')
        status = send_to_waf(path, user_agent=ua)
        if status == 403:
            blocked += 1
            print(f"  {PASS} BLOQUE  | {payload[:60]}")
        else:
            allowed += 1
            print(f"  {INFO} LAISSE  | {payload[:60]}  (HTTP {status})")
    print(f"  Resultat : {blocked} bloques / {len(payloads)} payloads")
    return blocked, len(payloads)


def main():
    print("=" * 65)
    print("  Simulation OWASP ZAP Active Scanner contre le WAF")
    print("  Cible : http://127.0.0.1:5000/proxy")
    print("=" * 65)

    total_blocked = 0
    total_payloads = 0

    # SQL Injection
    b, t = run_category(
        "SQL Injection (ZAP TestSQLInjection)",
        ZAP_SQLI_PAYLOADS,
        base_path="login?user=",
        ua="Mozilla/5.0 ZAP/2.14 Active Scanner"
    )
    total_blocked += b; total_payloads += t

    # Path Traversal
    b, t = run_category(
        "Path Traversal (ZAP TestPathTraversal)",
        ZAP_PATH_TRAVERSAL_PAYLOADS,
        base_path="",
        ua="Mozilla/5.0 ZAP/2.14 Active Scanner"
    )
    total_blocked += b; total_payloads += t

    # XSS
    b, t = run_category(
        "Cross-Site Scripting (ZAP TestCrossSiteScripting)",
        ZAP_XSS_PAYLOADS,
        base_path="search?q=",
        ua="Mozilla/5.0 ZAP/2.14 Active Scanner"
    )
    total_blocked += b; total_payloads += t

    # OS Command Injection
    b, t = run_category(
        "OS Command Injection (ZAP TestRemoteOSCommandInjection)",
        ZAP_CMDI_PAYLOADS,
        base_path="cmd?exec=",
        ua="Mozilla/5.0 ZAP/2.14 Active Scanner"
    )
    total_blocked += b; total_payloads += t

    # Remote File Include
    b, t = run_category(
        "Remote File Include (ZAP TestRemoteFileInclude)",
        ZAP_RFI_PAYLOADS,
        base_path="page?file=",
        ua="Mozilla/5.0 ZAP/2.14 Active Scanner"
    )
    total_blocked += b; total_payloads += t

    # Verification trafic normal non impacte
    print("\n--- Trafic normal (aucun blocage attendu) ---")
    normal_paths = ["/products", "/login", "/dashboard", "/api/data", "/index.html"]
    false_positives = 0
    for path in normal_paths:
        status = send_to_waf(path)
        if status == 403:
            false_positives += 1
            print(f"  {FAIL} FAUX POSITIF : {path} bloque abusivement !")
        else:
            print(f"  {PASS} AUTORISE : {path}  (HTTP {status})")


    # Bilan final
    block_rate = round(total_blocked / total_payloads * 100, 1) if total_payloads else 0
    print("\n" + "=" * 65)
    print("  BILAN OWASP ZAP SIMULATION")
    print("=" * 65)
    print(f"  Payloads testes   : {total_payloads}")
    print(f"  Bloques par WAF   : {total_blocked}")
    print(f"  Taux de detection : {block_rate}%")
    print(f"  Faux positifs     : {false_positives}")
    print("=" * 65)

    if false_positives == 0:
        print("  Aucun faux positif detecte.")
    else:
        print(f"  ATTENTION : {false_positives} faux positif(s) detecte(s).")


if __name__ == "__main__":
    main()
