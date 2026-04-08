import joblib
from flask import Flask, request, jsonify
import pandas as pd
import re

# Charger le modèle entraîné
model = joblib.load('waf_model.joblib')

# Fonction d'extraction des features (doit être identique à celle du notebook)
def extract_features_from_input(data):
    df = pd.DataFrame([data])
    df['path_length'] = df['request_path'].apply(lambda x: len(str(x)))
    df['param_count'] = df['request_path'].apply(lambda x: str(x).count('&'))
    keywords = ['select', 'union', 'script', '../', 'or 1=1', 'cmd.exe', 'passwd', 'shell', 'upload', 'phpmyadmin', 'admin']
    for kw in keywords:
        df[f'has_{kw.replace("/", "slash").replace(".", "dot").replace(" ", "_")}'] = df['request_path'].str.lower().apply(lambda x: int(kw in x))
    df['special_char_count'] = df['request_path'].apply(lambda x: len(re.findall(r'[;=(){}\[\]<>]', str(x))))
    df['method_GET'] = (df['request_method'] == 'GET').astype(int)
    df['method_POST'] = (df['request_method'] == 'POST').astype(int)
    df['method_PUT'] = (df['request_method'] == 'PUT').astype(int)
    df['method_DELETE'] = (df['request_method'] == 'DELETE').astype(int)
    for code in [200, 301, 400, 401, 403, 404, 500]:
        df[f'status_{code}'] = (df['status_code'] == code).astype(int)
    df['user_agent_sqlmap'] = df['user_agent'].str.contains('sqlmap', case=False, na=False).astype(int)
    df['user_agent_nikto'] = df['user_agent'].str.contains('nikto', case=False, na=False).astype(int)
    df['user_agent_curl'] = df['user_agent'].str.contains('curl', case=False, na=False).astype(int)
    df['user_agent_python'] = df['user_agent'].str.contains('python', case=False, na=False).astype(int)
    # Sélectionner les mêmes features que pour l'entraînement
    features = [col for col in df.columns if col not in ['timestamp', 'ip_address', 'request_method', 'request_path', 'status_code', 'user_agent']]
    return df[features]

app = Flask(__name__)

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    X = extract_features_from_input(data)
    pred = model.predict(X)[0]
    proba = model.predict_proba(X)[0][1] if hasattr(model, 'predict_proba') else None
    return jsonify({
        'prediction': int(pred),
        'probability_malicious': float(proba) if proba is not None else None
    })

if __name__ == '__main__':
    app.run(debug=True)
