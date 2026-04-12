"""
Tests du WAF intelligent - Suite complete (Semaine 4)

Lancer le serveur avant les tests :
  python waf_flask_app.py

Puis dans un autre terminal :
  python test_flask_waf.py
"""

import sys
import requests

BASE_URL = 'http://127.0.0.1:5000'
PASS     = '\033[92m[PASS]\033[0m'
FAIL     = '\033[91m[FAIL]\033[0m'
INFO     = '\033[94m[INFO]\033[0m'


def _req(method, path, **kwargs):
    return requests.request(method, BASE_URL + path, timeout=5, **kwargs)


# ----------------------- Tests infrastructure --------------------------------------
def test_health():
    r = _req('GET', '/health')
    assert r.status_code == 200, f"HTTP {r.status_code}"
    d = r.json()
    assert d['status'] == 'ok'
    assert d['model_loaded'] is True, "Modele non charge !"
    print(f"{PASS} /health           - modele={d['model_type']}")


def test_index():
    r = _req('GET', '/')
    assert r.status_code == 200
    d = r.json()
    assert 'endpoints' in d
    print(f"{PASS} /               - {d['service']}")


def test_stats_initial():
    r = _req('GET', '/stats')
    assert r.status_code == 200
    d = r.json()
    assert 'total' in d and 'blocked' in d
    print(f"{PASS} /stats             - total={d['total']}, blocked={d['blocked']}, taux={d['block_rate']}%")


# ----------------------- Tests /predict -------------------------------------------
def test_normal_request():
    data = {
        'timestamp':      '2023-10-26T08:00:00',
        'ip_address':     '192.168.1.10',
        'request_method': 'GET',
        'request_path':   '/products',
        'status_code':    200,
        'user_agent':     'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/107.0'
    }
    r = _req('POST', '/predict', json=data)
    assert r.status_code == 200
    d = r.json()
    assert d['prediction'] == 0, f"Attendu NORMAL (0), obtenu {d['prediction']}"
    prob = f"{d['probability_malicious']:.3f}" if d.get('probability_malicious') is not None else 'N/A'
    print(f"{PASS} /predict normal    - verdict={d['verdict']}, proba={prob}")


def test_sqli_attack():
    data = {
        'timestamp':      '2023-10-26T08:01:00',
        'ip_address':     '10.0.0.5',
        'request_method': 'GET',
        'request_path':   '/admin/users.php?id=1%20UNION%20SELECT%20null,null,version()--',
        'status_code':    200,
        'user_agent':     'sqlmap/1.6.10 (http://sqlmap.org)'
    }
    r = _req('POST', '/predict', json=data)
    assert r.status_code == 200
    d = r.json()
    assert d['prediction'] == 1, f"SQLi non detectee (prediction={d['prediction']})"
    prob = f"{d['probability_malicious']:.3f}" if d.get('probability_malicious') is not None else 'N/A'
    print(f"{PASS} /predict sqli      - verdict={d['verdict']}, proba={prob}")


def test_path_traversal():
    data = {
        'timestamp':      '2023-10-26T08:02:00',
        'ip_address':     '10.0.0.6',
        'request_method': 'GET',
        'request_path':   '/../../../../etc/passwd',
        'status_code':    200,
        'user_agent':     'curl/7.64.1'
    }
    r = _req('POST', '/predict', json=data)
    assert r.status_code == 200
    d = r.json()
    label = 'MALICIEUX' if d['prediction'] == 1 else 'NORMAL'
    mark  = PASS if d['prediction'] == 1 else INFO
    print(f"{mark} /predict traversal - verdict={label}")


def test_nikto_scan():
    data = {
        'timestamp':      '2023-10-26T08:03:00',
        'ip_address':     '10.0.0.7',
        'request_method': 'GET',
        'request_path':   '/phpmyadmin/index.php',
        'status_code':    200,
        'user_agent':     'Nikto/2.1.6'
    }
    r = _req('POST', '/predict', json=data)
    assert r.status_code == 200
    d = r.json()
    assert d['prediction'] == 1, f"Nikto non detecte (prediction={d['prediction']})"
    print(f"{PASS} /predict nikto     - verdict={d['verdict']}")


def test_shell_upload():
    data = {
        'timestamp':      '2023-10-26T08:04:00',
        'ip_address':     '10.0.0.8',
        'request_method': 'POST',
        'request_path':   '/upload.php?file=shell.php',
        'status_code':    200,
        'user_agent':     'Python-requests/2.28.1'
    }
    r = _req('POST', '/predict', json=data)
    assert r.status_code == 200
    d = r.json()
    label = 'MALICIEUX' if d['prediction'] == 1 else 'NORMAL'
    mark  = PASS if d['prediction'] == 1 else INFO
    print(f"{mark} /predict shell     - verdict={label}")


# ----------------------- Tests /analyze -------------------------------------------
def test_analyze_normal():
    data = {
        'timestamp':      '2023-10-26T08:05:00',
        'ip_address':     '192.168.1.20',
        'request_method': 'GET',
        'request_path':   '/dashboard',
        'status_code':    200,
        'user_agent':     'Mozilla/5.0 Chrome/107.0'
    }
    r = _req('POST', '/analyze', json=data)
    assert r.status_code == 200
    d = r.json()
    assert 'features' in d
    assert 'verdict' in d
    print(f"{PASS} /analyze normal    - verdict={d['verdict']}, {len(d['features'])} features")


def test_analyze_malicious():
    data = {
        'timestamp':      '2023-10-26T08:06:00',
        'ip_address':     '10.0.0.9',
        'request_method': 'GET',
        'request_path':   "/login?user=' OR 1=1--",
        'status_code':    200,
        'user_agent':     'sqlmap/1.6.10'
    }
    r = _req('POST', '/analyze', json=data)
    assert r.status_code == 200
    d = r.json()
    assert d['verdict'] == 'MALICIEUX', f"Attendu MALICIEUX, obtenu {d['verdict']}"
    top_features = {k: v for k, v in d['features'].items() if v != 0}
    print(f"{PASS} /analyze malicious - verdict={d['verdict']}, features actives={len(top_features)}")


# ----------------------- Tests /proxy (mode WAF temps reel) -----------------------
def test_proxy_blocks_sqli():
    r = _req(
        'GET', '/proxy/admin/users.php',
        params={'id': '1 UNION SELECT null,version()--'},
        headers={'User-Agent': 'sqlmap/1.6.10'}
    )
    assert r.status_code == 403, f"Attendu 403 (bloque), obtenu {r.status_code}"
    d = r.json()
    assert 'bloquee' in d.get('error', '').lower() or 'malicieux' in d.get('reason', '').lower()
    print(f"{PASS} /proxy bloque      - SQLi bloquee (HTTP 403)")


def test_proxy_allows_normal():
    r = _req(
        'GET', '/proxy/get',
        headers={'User-Agent': 'Mozilla/5.0 Chrome/107.0'}
    )
    # 200 (backend repond) ou 502 (backend injoignable) - jamais 403
    assert r.status_code != 403, "Requete normale incorrectement bloquee !"
    mark = PASS if r.status_code == 200 else INFO
    print(f"{mark} /proxy normal      - HTTP {r.status_code} (403 absent = OK)")


# ----------------------- Cas limites ----------------------------------------------
def test_missing_body():
    r = _req('POST', '/predict', data='invalid json', headers={'Content-Type': 'application/json'})
    # 400 ou 200 selon la tolerance - ne doit pas crasher (5xx)
    assert r.status_code < 500, f"Erreur serveur inattendue : {r.status_code}"
    print(f"{PASS} corps invalide     - HTTP {r.status_code} (pas de crash)")


def test_stats_updated():
    r = _req('GET', '/stats')
    d = r.json()
    assert d['total'] > 0, "Compteur total non incremente"
    print(f"{PASS} /stats final       - total={d['total']}, blocked={d['blocked']}, taux={d['block_rate']}%")


# ----------------------- Runner principal ------------------------------------------
def run_all():
    print('=' * 60)
    print('  Tests WAF intelligent - Suite complete')
    print('=' * 60)

    tests = [
        # Infrastructure
        test_health,
        test_index,
        test_stats_initial,
        # Classification /predict
        test_normal_request,
        test_sqli_attack,
        test_path_traversal,
        test_nikto_scan,
        test_shell_upload,
        # Analyse /analyze
        test_analyze_normal,
        test_analyze_malicious,
        # Proxy temps reel
        test_proxy_blocks_sqli,
        test_proxy_allows_normal,
        # Cas limites
        test_missing_body,
        test_stats_updated,
    ]

    passed = failed = 0
    for test_fn in tests:
        try:
            test_fn()
            passed += 1
        except AssertionError as exc:
            print(f"{FAIL} {test_fn.__name__}: {exc}")
            failed += 1
        except requests.exceptions.ConnectionError:
            print(f"\n  Serveur Flask inaccessible sur {BASE_URL}")
            print("  Lancez d'abord : python waf_flask_app.py\n")
            sys.exit(1)

    print('=' * 60)
    print(f'  Resultat : {passed} reussis / {failed} echecs / {len(tests)} tests')
    print('=' * 60)
    return failed == 0


if __name__ == '__main__':
    success = run_all()
    sys.exit(0 if success else 1)
