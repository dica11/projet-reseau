# WAF intelligent - Detection d'attaques web par Machine Learning

Projet reseau - Avril 2026

Conception et implementation d'un Web Application Firewall (WAF) intelligent capable de detecter en temps reel les requetes HTTP malicieuses a l'aide de techniques de machine learning.

---

## Objectifs

- Classifier automatiquement les requetes web (normale vs malicieuse)
- Comparer 4 algorithmes de machine learning
- Deployer un proxy WAF operationnel via Flask
- Valider le systeme avec une suite de tests automatises

---

## Resultats obtenus

| Modele | Accuracy | Precision | Recall | F1-score |
|---|---|---|---|---|
| **Neural Network (MLP)** | **1.000** | **1.000** | **1.000** | **1.000** |
| Logistic Regression | 0.900 | 1.000 | 0.500 | 0.667 |
| Random Forest | 0.900 | 1.000 | 0.500 | 0.667 |
| SVM | 0.900 | 1.000 | 0.500 | 0.667 |

**Suite de tests : 14/14 reussis (100 %)**

**Simulation OWASP ZAP Active Scanner : 47/50 payloads bloques (94 %) — 0 faux positif**

| Categorie ZAP | Bloques / Total |
|---|---|
| SQL Injection | 15/15 |
| XSS | 9/9 |
| Command Injection | 10/10 |
| Remote File Include | 4/4 |
| Path Traversal | 9/12 |

---

## Structure du projet

```
projet-reseau/
|-- waf_etapes.ipynb        # Notebook ML complet (exploration, features, modeles)
|-- waf_flask_app.py        # Proxy WAF Flask avec 5 endpoints
|-- test_flask_waf.py       # Suite de 14 tests automatises
|-- test_owasp_zap.py       # Simulation OWASP ZAP active scanner (50 payloads reels)
|-- waf_model.joblib        # Modele MLPClassifier exporte (sklearn)
|-- donnees_nettoyees.csv   # Dataset nettoye apres feature engineering
|-- rapport.md              # Rapport scientifique complet (~15 pages)
|-- presentation_slides.md  # Presentation 10 slides
|-- setup_env.ps1           # Script d'installation de l'environnement Python
```

---

## Installation et demarrage rapide

### Prerequis
- Python 3.12
- Git

### 1. Cloner le repository
```bash
git clone https://github.com/dica11/projet-reseau.git
cd projet-reseau
```

### 2. Creer et activer l'environnement virtuel
```bash
# Windows PowerShell
python -m venv waf_env
waf_env\Scripts\Activate.ps1

# ou utiliser le script fourni
.\setup_env.ps1
```

### 3. Installer les dependances
```bash
pip install -r requirements.txt
```

### 4. Generer le modele (executer le notebook)
Ouvrir `waf_etapes.ipynb` dans VS Code ou Jupyter et executer toutes les cellules.  
Cela genere `waf_model.joblib`.

### 5. Demarrer le serveur WAF
```bash
python waf_flask_app.py
```
Le serveur demarre sur `http://localhost:5000`.

### 6. Lancer les tests
Dans un second terminal :
```bash
python test_flask_waf.py
```

### 7. Simuler une attaque OWASP ZAP (optionnel)
Avec le serveur WAF actif :
```bash
python test_owasp_zap.py
```

---

## Endpoints du proxy WAF

| Methode | Endpoint | Description |
|---|---|---|
| GET | `/` | Statut du service |
| GET | `/health` | Sante du service et du modele |
| GET | `/stats` | Statistiques de trafic en temps reel |
| POST | `/predict` | Classification JSON d'une requete |
| POST | `/analyze` | Classification + 29 features detaillees |
| ANY | `/proxy/<path>` | Proxy WAF en temps reel |

### Exemple - Predire une requete
```bash
curl -X POST http://localhost:5000/predict \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2026-04-07T10:00:00",
    "ip_address": "192.168.1.10",
    "request_method": "GET",
    "request_path": "/products",
    "status_code": 200,
    "user_agent": "Mozilla/5.0 Chrome/107.0"
  }'
```

Reponse :
```json
{
  "prediction": 0,
  "probability_malicious": 0.021,
  "verdict": "AUTORISE"
}
```

### Exemple - Attaque SQLi bloquee
```bash
curl -X GET "http://localhost:5000/proxy/admin/users.php?id=1+UNION+SELECT+null,version()--" \
  -H "User-Agent: sqlmap/1.6.10"
```

Reponse :
```json
HTTP 403
{
  "error": "Requete bloquee par le WAF",
  "reason": "Trafic malicieux detecte par le modele ML",
  "probability": 1.0
}
```

---

## Features extraites (29 au total)

| Categorie | Features |
|---|---|
| Structure URL | `path_length`, `param_count` |
| Mots-cles suspects | `has_select`, `has_union`, `has_script`, `has_admin`, `has_passwd`, ... (11) |
| Caracteres speciaux | `special_char_count` |
| Methode HTTP | `method_GET`, `method_POST`, `method_PUT`, `method_DELETE` |
| Code statut | `status_200`, `status_301`, `status_400`, `status_401`, `status_403`, `status_404`, `status_500` |
| User-agent | `user_agent_sqlmap`, `user_agent_nikto`, `user_agent_curl`, `user_agent_python` |

---

## Tests couverts

| Test | Resultat |
|---|---|
| Service /health | PASS |
| Page d'accueil / | PASS |
| Statistiques /stats | PASS |
| Requete GET normale `/products` | PASS - AUTORISE (2.1%) |
| SQLi `UNION SELECT` + sqlmap UA | PASS - BLOQUE (100.0%) |
| Path traversal `/etc/passwd` | PASS - BLOQUE (100.0%) |
| Scan Nikto `/phpmyadmin` | PASS - BLOQUE (98.9%) |
| Shell upload `/upload.php?file=shell.php` | PASS - BLOQUE (100.0%) |
| Analyse /analyze requete normale | PASS - 29 features |
| Analyse /analyze requete malicieuse | PASS - MALICIEUX |
| Proxy /proxy SQLi bloquee HTTP 403 | PASS |
| Proxy /proxy requete normale transféree | PASS - HTTP 200 |
| Corps JSON invalide | PASS - HTTP 400 (pas de crash) |
| Compteurs /stats mis a jour | PASS |

---

## Technologies utilisees

- **Python 3.12**
- **scikit-learn 1.8** - MLPClassifier, RandomForest, SVM, LogisticRegression
- **pandas 3.0** - manipulation des donnees
- **Flask** - proxy WAF et API REST
- **joblib** - serialisation du modele
- **Jupyter Notebook** - exploration et visualisation
- **python-owasp-zap-v2.4** - payloads OWASP ZAP active scanner

---

## Livrables

| Livrable | Fichier |
|---|---|
| Notebook ML complet | `waf_etapes.ipynb` |
| Prototype WAF | `waf_flask_app.py` |
| Tests automatises (14/14) | `test_flask_waf.py` |
| Simulation OWASP ZAP (94%) | `test_owasp_zap.py` |
| Rapport scientifique | `rapport.md` |
| Presentation 10 slides | `presentation_slides.md` |
| Modele exporte | `waf_model.joblib` |
| Dataset nettoye | `donnees_nettoyees.csv` |
| Dependances Python | `requirements.txt` |

---

## Auteurs

- Projet reseau - Cours securite des reseaux - Avril 2026
- Repository : https://github.com/dica11/projet-reseau
