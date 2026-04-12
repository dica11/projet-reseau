"""
WAF intelligent - Proxy Flask avec classification ML en temps reel
Semaine 3 : Developpement du prototype proxy WAF

Endpoints :
    GET  /          - statut et liste des routes
    GET  /health    - etat du service et du modele
    GET  /stats     - statistiques de trafic en temps reel
    POST /predict   - classification JSON d'une requete
    POST /analyze   - classification + detail des features
    ANY  /proxy/<path> - proxy WAF : intercepte, classe, bloque ou transfere

Usage :
    python waf_flask_app.py
    Configurer TARGET_HOST pour pointer vers le serveur backend a proteger.
"""

import os
import re
import logging

import joblib
import pandas as pd
import requests as req_lib
from datetime import datetime
from flask import Flask, request, jsonify, Response

# ----------------------- Configuration ----------------------------------------
MODEL_PATH   = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'waf_model.joblib')
TARGET_HOST  = os.getenv('TARGET_HOST', 'http://httpbin.org')   # backend a proteger
LOG_FILE     = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'waf_access.log')
PORT         = int(os.getenv('WAF_PORT', 5000))

# ----------------------- Logging ----------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ----------------------- Chargement du modele ML ------------------------------
try:
    model = joblib.load(MODEL_PATH)
    logger.info(f"Modele charge : {MODEL_PATH} ({type(model).__name__})")
except FileNotFoundError:
    logger.error(f"Modele introuvable : {MODEL_PATH}")
    logger.error("Lancez d'abord waf_etapes.ipynb pour generer waf_model.joblib")
    model = None

# ----------------------- Statistiques runtime ---------------------------------
stats = {
    'total':   0,
    'blocked': 0,
    'allowed': 0,
    'started': datetime.now().isoformat()
}

# ----------------------- Feature engineering ----------------------------------
KEYWORDS = ['select', 'union', 'script', '../', 'or 1=1',
            'cmd.exe', 'passwd', 'shell', 'upload', 'phpmyadmin', 'admin']

HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE']
STATUS_CODES = [200, 301, 400, 401, 403, 404, 500]

DROP_COLS = ['timestamp', 'ip_address', 'request_method',
             'request_path', 'status_code', 'user_agent']


def extract_features(data: dict) -> pd.DataFrame:
    """Extrait les features d'une requete HTTP - identique au notebook."""
    df = pd.DataFrame([data])

    # Longueur du chemin et nombre de parametres
    df['path_length']  = df['request_path'].apply(lambda x: len(str(x)))
    df['param_count']  = df['request_path'].apply(lambda x: str(x).count('&'))

    # Mots-cles suspects dans le chemin
    for kw in KEYWORDS:
        col = f'has_{kw.replace("/", "slash").replace(".", "dot").replace(" ", "_")}'
        df[col] = df['request_path'].str.lower().apply(lambda x: int(kw in x))

    # Caracteres speciaux suspects
    df['special_char_count'] = df['request_path'].apply(
        lambda x: len(re.findall(r'[;=(){}\[\]<>]', str(x))))

    # Methode HTTP (one-hot)
    for method in HTTP_METHODS:
        df[f'method_{method}'] = (df['request_method'] == method).astype(int)

    # Code statut HTTP (one-hot)
    for code in STATUS_CODES:
        df[f'status_{code}'] = (df['status_code'] == code).astype(int)

    # User-agent suspects
    df['user_agent_sqlmap']  = df['user_agent'].str.contains('sqlmap',  case=False, na=False).astype(int)
    df['user_agent_nikto']   = df['user_agent'].str.contains('nikto',   case=False, na=False).astype(int)
    df['user_agent_curl']    = df['user_agent'].str.contains('curl',    case=False, na=False).astype(int)
    df['user_agent_python']  = df['user_agent'].str.contains('python',  case=False, na=False).astype(int)

    feature_cols = [c for c in df.columns if c not in DROP_COLS]
    return df[feature_cols]


def classify(data: dict) -> dict:
    """Retourne prediction (0/1) et probabilite de classe malicieuse."""
    if model is None:
        return {'prediction': 0, 'probability': None, 'error': 'Modele non charge'}
    try:
        X    = extract_features(data)
        pred = int(model.predict(X)[0])
        prob = float(model.predict_proba(X)[0][1]) if hasattr(model, 'predict_proba') else None
        return {'prediction': pred, 'probability': prob}
    except Exception as exc:
        logger.error(f"Erreur classification : {exc}")
        return {'prediction': 0, 'probability': None, 'error': str(exc)}


def _log_request(verdict: str, ip: str, method: str, path: str, prob=None):
    prob_str = f" | proba={prob:.1%}" if prob is not None else ''
    if verdict == 'BLOQUE':
        logger.warning(f"BLOQUE   | {ip} | {method} {path}{prob_str}")
    else:
        logger.info(f"AUTORISE | {ip} | {method} {path}{prob_str}")


def _get_json_payload():
    data = request.get_json(force=True)
    if not data:
        return None, (jsonify({'error': 'Corps JSON requis'}), 400)
    return data, None


def _update_stats_and_log(prediction: int, probability, ip: str, method: str, path: str):
    stats['total'] += 1
    if prediction == 1:
        stats['blocked'] += 1
    else:
        stats['allowed'] += 1
    _log_request('BLOQUE' if prediction == 1 else 'AUTORISE', ip, method, path, probability)


def _build_request_metadata(path: str) -> tuple[str, dict]:
    req_path = '/' + path + ('?' + request.query_string.decode() if request.query_string else '')
    req_data = {
        'timestamp': datetime.now().isoformat(),
        'ip_address': request.remote_addr or '0.0.0.0',
        'request_method': request.method,
        'request_path': req_path,
        'status_code': 200,
        'user_agent': request.headers.get('User-Agent', '')
    }
    return req_path, req_data


# ----------------------- Flask -------------------------------------------------
app = Flask(__name__)


@app.route('/', methods=['GET'])
def index():
    """Page de statut du WAF."""
    return jsonify({
        'service': 'WAF intelligent - Proxy Flask ML',
        'version': '1.0',
        'model':   type(model).__name__ if model else 'non charge',
        'backend': TARGET_HOST,
        'endpoints': {
            'GET  /health':       'etat du service',
            'GET  /stats':        'statistiques de trafic',
            'POST /predict':      'classification JSON',
            'POST /analyze':      'classification + features detaillees',
            'ANY  /proxy/<path>': 'proxy WAF en temps reel',
        },
        'stats': stats
    })


@app.route('/health', methods=['GET'])
def health():
    """Verification de sante du service."""
    return jsonify({
        'status':       'ok',
        'model_loaded': model is not None,
        'model_type':   type(model).__name__ if model else None,
        'backend':      TARGET_HOST,
        'uptime_since': stats['started']
    })


@app.route('/stats', methods=['GET'])
def get_stats():
    """Statistiques en temps reel."""
    return jsonify({
        **stats,
        'block_rate': round(stats['blocked'] / stats['total'] * 100, 2)
                      if stats['total'] > 0 else 0
    })


@app.route('/predict', methods=['POST'])
def predict():
    """Classe une requete et retourne prediction + probabilite."""
    data, error_response = _get_json_payload()
    if error_response:
        return error_response

    result = classify(data)
    _update_stats_and_log(
        prediction=result['prediction'],
        probability=result.get('probability'),
        ip=data.get('ip_address', '?'),
        method=data.get('request_method', '?'),
        path=data.get('request_path', '?')
    )
    return jsonify({
        'prediction':          result['prediction'],
        'probability_malicious': result.get('probability'),
        'verdict':             'BLOQUE' if result['prediction'] == 1 else 'AUTORISE'
    })


@app.route('/analyze', methods=['POST'])
def analyze():
    """Analyse detaillee : classification + toutes les features extraites."""
    data, error_response = _get_json_payload()
    if error_response:
        return error_response
    try:
        result = classify(data)
        X      = extract_features(data)
        label  = 'MALICIEUX' if result['prediction'] == 1 else 'NORMAL'
        return jsonify({
            'verdict':               label,
            'prediction':            result['prediction'],
            'probability_malicious': result.get('probability'),
            'features':              X.iloc[0].to_dict(),
            'request': {
                'method': data.get('request_method'),
                'path':   data.get('request_path'),
                'ip':     data.get('ip_address'),
            }
        })
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500


@app.route('/proxy', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'])
@app.route('/proxy/<path:path>',            methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'])
def proxy(path):
    """
    Proxy WAF en temps reel.
    1. Intercepte la requete entrante.
    2. Extrait les features et classe via le modele ML.
    3. Bloque (403) si malicieuse - sinon transfere au backend TARGET_HOST.
    """
    req_path, req_data = _build_request_metadata(path)

    result = classify(req_data)
    _update_stats_and_log(
        prediction=result.get('prediction', 0),
        probability=result.get('probability'),
        ip=req_data['ip_address'],
        method=request.method,
        path=req_path
    )

    # -- Blocage --------------------------------------------------------------
    if result.get('prediction') == 1:
        return jsonify({
            'error':       'Requete bloquee par le WAF',
            'reason':      'Trafic malicieux detecte par le modele ML',
            'path':        req_path,
            'probability': result.get('probability')
        }), 403

    # -- Transfert vers le backend --------------------------------------------
    try:
        target_url = TARGET_HOST.rstrip('/') + '/' + path
        headers = {k: v for k, v in request.headers
                   if k.lower() not in ('host', 'content-length',
                                        'transfer-encoding', 'connection')}
        resp = req_lib.request(
            method=request.method,
            url=target_url,
            headers=headers,
            data=request.get_data(),
            params=request.args,
            timeout=10,
            allow_redirects=False
        )
        return Response(resp.content,
                        status=resp.status_code,
                        headers=dict(resp.headers))

    except req_lib.exceptions.ConnectionError:
        return jsonify({'error': f'Backend inaccessible : {TARGET_HOST}'}), 502
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500


# ----------------------- Demarrage --------------------------------------------
if __name__ == '__main__':
    print('=' * 62)
    print('  WAF intelligent - Proxy Flask ML')
    print(f'  Modele  : {type(model).__name__ if model else "NON CHARGE"}')
    print(f'  Backend : {TARGET_HOST}')
    print(f'  Port    : {PORT}')
    print(f'  Logs    : {LOG_FILE}')
    print('=' * 62)
    app.run(host='0.0.0.0', port=PORT, debug=True)
