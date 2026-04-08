# Rapport scientifique
# WAF intelligent basé sur le Machine Learning
## Détection automatique de requêtes web malicieuses par apprentissage automatique

**Auteur :** Équipe projet-reseau  
**Date :** Avril 2026  
**Repository :** https://github.com/dica11/projet-reseau

---

## Résumé

Ce rapport présente la conception, l'implémentation et l'évaluation d'un Web Application Firewall (WAF) intelligent fondé sur des techniques de machine learning. L'objectif est de dépasser les limites des WAF basés sur des règles statiques en s'appuyant sur un modèle d'apprentissage automatique capable de classer en temps réel les requêtes HTTP comme normales ou malicieuses. Quatre algorithmes ont été comparés : régression logistique, forêt aléatoire, SVM et réseau de neurones. Le meilleur modèle (MLPClassifier) atteint un F1-score de 1.0 sur l'ensemble de test. Un prototype complet sous Flask a été déployé et validé par une suite de 14 tests automatisés (100 % de réussite).

---

## 1. Introduction

### 1.1 Contexte et enjeux

La sécurité des applications web est aujourd'hui un enjeu critique. Selon le rapport Verizon Data Breach Investigations (2024), plus de 40 % des violations de données impliquent des applications web. Les attaques les plus fréquentes — injections SQL, traversées de répertoires, scans automatiques — ciblent directement les serveurs applicatifs et peuvent conduire à l'exfiltration de données sensibles, la prise de contrôle de systèmes ou l'interruption de service.

Les Web Application Firewalls (WAF) constituent la défense de première ligne. Cependant, les solutions classiques (ModSecurity, AWS WAF, etc.) reposent sur des signatures statiques ou des listes de règles maintenues manuellement. Cette approche présente deux limites fondamentales :

1. **Réactivité faible** : un nouveau vecteur d'attaque non répertorié n'est pas détecté avant la mise à jour des règles.
2. **Taux de faux positifs élevé** : des règles trop génériques bloquent du trafic légitime, nuisant à l'expérience utilisateur.

### 1.2 Problématique

Comment concevoir un WAF capable d'apprendre automatiquement les caractéristiques distinguant une requête normale d'une requête malicieuse, sans nécessiter de mise à jour manuelle des règles ?

### 1.3 Objectifs du projet

- Construire un dataset synthétique représentatif du trafic web réel et malicieux.
- Extraire des features pertinentes à partir des métadonnées HTTP.
- Entraîner et comparer plusieurs modèles de machine learning.
- Déployer le meilleur modèle dans un proxy WAF opérationnel (Flask).
- Valider le système par des tests automatisés couvrant des scenarios d'attaque réels.

---

## 2. État de l'art

### 2.1 Principales attaques web

| Attaque | Description | Exemple |
|---|---|---|
| **SQL Injection (SQLi)** | Injection de code SQL dans les paramètres d'URL ou de formulaire | `?id=1 UNION SELECT null,version()--` |
| **Path Traversal** | Navigation hors du répertoire web autorisé | `/../../../../etc/passwd` |
| **XSS (Cross-Site Scripting)** | Injection de code JavaScript dans des réponses web | `<script>alert(1)</script>` |
| **Scan automatique** | Reconnaissance de vulnérabilités par des outils (Nikto, sqlmap) | User-Agent: `Nikto/2.1.6` |
| **Shell upload** | Dépôt d'un fichier exécutable malicieux via une interface d'upload | `/upload.php?file=shell.php` |

### 2.2 WAF traditionnels

Les solutions commerciales et open-source reposent principalement sur :

- **Signatures statiques** (ModSecurity avec le Core Rule Set OWASP) : efficaces contre les attaques connues, contournables par obfuscation.
- **Listes noires/blanches** d'IP ou de user-agents : maintenance coûteuse, peu scalable.
- **Analyse heuristique** : détection de patterns suspects, source de nombreux faux positifs.

**Limites identifiées :** rigidité, manque d'adaptation aux nouvelles attaques, difficulté à traiter des volumes importants de trafic hétérogène.

### 2.3 Apports du Machine Learning

L'apprentissage automatique permet d'apprendre des représentations statistiques du trafic normal et anormal, offrant :

- **Généralisation** : détection d'attaques inédites présentant des patterns similaires aux attaques connues.
- **Adaptabilité** : le modèle peut être ré-entraîné sur de nouvelles données.
- **Classification probabiliste** : fourniture d'un score de confiance, permettant de graduer la réponse.

Des travaux récents (Sharma & Singh, 2023 ; Nguyen et al., 2024) montrent que les approches Random Forest et Deep Learning surpassent significativement les règles statiques sur des jeux de données réels (CICIDS, HTTP CSIC 2010).

---

## 3. Méthodologie

### 3.1 Dataset synthétique

En l'absence de données réelles disponibles dans le cadre de ce projet, un dataset synthétique a été généré pour simuler un trafic web réaliste.

**Composition :** 100 requêtes HTTP, dont 21 malicieuses (21 %).

**Requêtes normales (79 %)** — Chemins : `/`, `/index.html`, `/login`, `/products`, `/api/data`, `/dashboard`

**Requêtes malicieuses (21 %)** — Incluant :
- Injections SQL : `/admin/users.php?id=1 UNION SELECT null,null,version()--`
- Path traversal : `/../../../../windows/system32/cmd.exe`
- Exploitation de fichiers système : `/etc/passwd`
- Accès phpmyadmin : `/phpmyadmin/index.php?pma_username=root`
- Webshells : `/shell.php`, `/upload.php?file=evil.php`
- Scan WordPress : `/wp-admin/admin-ajax.php`

**User-agents** : navigateurs légitimes, curl, Python-requests, Nikto, sqlmap.

### 3.2 Extraction de features (Feature Engineering)

29 features binaires ou numériques ont été extraites de chaque requête HTTP :

| Catégorie | Features | Nombre |
|---|---|---|
| Longueur et structure du chemin | `path_length`, `param_count` | 2 |
| Mots-clés suspects | `has_select`, `has_union`, `has_script`, `has_slash_slash`, `has_or_1_1`, `has_cmd_dot_exe`, `has_passwd`, `has_shell`, `has_upload`, `has_phpmyadmin`, `has_admin` | 11 |
| Caractères spéciaux | `special_char_count` | 1 |
| Méthode HTTP (one-hot) | `method_GET/POST/PUT/DELETE` | 4 |
| Code statut HTTP (one-hot) | `status_200/301/400/401/403/404/500` | 7 |
| User-agent suspect | `user_agent_sqlmap`, `user_agent_nikto`, `user_agent_curl`, `user_agent_python` | 4 |
| **Total** | | **29** |

### 3.3 Modèles de machine learning

Quatre algorithmes de classification supervisée ont été évalués :

| Modèle | Hyperparamètres | Justification |
|---|---|---|
| **Logistic Regression** | `max_iter=1000` | Baseline interprétable |
| **Random Forest** | `n_estimators=100, random_state=42` | Robuste, gère les features non linéaires |
| **SVM** | `kernel=rbf, random_state=42` | Efficace sur espaces de haute dimension |
| **Neural Network (MLP)** | `max_iter=500, random_state=42` | Capture les interactions complexes |

**Séparation train/test :** 80/20 stratifiée (80 exemples d'entraînement, 20 de test), `random_state=42`.

---

## 4. Résultats expérimentaux

### 4.1 Performances comparées

| Modèle | Accuracy | Precision | Recall | F1-score |
|---|---|---|---|---|
| **Neural Network (MLP)** | **1.000** | **1.000** | **1.000** | **1.000** |
| Logistic Regression | 0.900 | 1.000 | 0.500 | 0.667 |
| Random Forest | 0.900 | 1.000 | 0.500 | 0.667 |
| SVM | 0.900 | 1.000 | 0.500 | 0.667 |

Le **MLPClassifier** (réseau de neurones multicouche) domine nettement avec un F1-score parfait de 1.0, contre 0.667 pour les trois autres modèles.

L'écart s'explique par le **recall** : le MLP détecte 100 % des requêtes malicieuses, tandis que les autres modèles n'en détectent que 50 % (recall = 0.5). La precision étant de 1.0 pour tous, il n'y a aucun faux positif dans les quatre cas.

### 4.2 Matrice de confusion — Neural Network (meilleur modèle)

```
                Prédit NORMAL   Prédit MALICIEUX
Réel NORMAL          16               0          ← 0 faux positifs
Réel MALICIEUX        0               4          ← 0 faux négatifs
```

**Interprétation :**
- **16 vrais négatifs** : toutes les requêtes normales correctement autorisées.
- **4 vrais positifs** : toutes les requêtes malicieuses correctement détectées.
- **0 faux positifs** : aucun blocage abusif de trafic légitime.
- **0 faux négatifs** : aucune attaque non détectée.

### 4.3 Tests d'attaque sur le proxy WAF

La suite de 14 tests automatisés (`test_flask_waf.py`) valide le comportement du proxy en conditions réelles :

| Test | Résultat | Probabilité malicieuse |
|---|---|---|
| Requête GET normale `/products` | AUTORISÉ | 2.1% |
| SQLi `UNION SELECT` (sqlmap UA) |  BLOQUÉ (HTTP 403) | 100.0% |
| Path traversal `/../../../../etc/passwd` |  BLOQUÉ | 100.0% |
| Scan Nikto `/phpmyadmin/index.php` | BLOQUÉ | 98.9% |
| Shell upload `/upload.php?file=shell.php` |  BLOQUÉ | 100.0% |
| `/proxy` SQLi (trafic HTTP réel) |  BLOQUÉ (HTTP 403) | 100.0% |
| `/proxy` requête normale |  TRANSFÉRÉ (HTTP 200) | 0.1% |

**Résultat global : 14/14 tests réussis (100 %)**

### 4.4 Simulation OWASP ZAP Active Scanner

Un second script (`test_owasp_zap.py`) reproduit les payloads réels de l'active scanner OWASP ZAP en les envoyant sur le proxy WAF. Les payloads proviennent directement du code source des modules ZAP (`zap-extensions/addOns/ascanrules`).

| Catégorie ZAP | Payloads | Bloqués | Taux |
|---|---|---|---|
| SQL Injection (`TestSQLInjection`) | 15 | 15 | 100 % |
| Path Traversal (`TestPathTraversal`) | 12 | 9 | 75 % |
| XSS (`TestCrossSiteScripting`) | 9 | 9 | 100 % |
| Command Injection (`TestRemoteOSCommandInjection`) | 10 | 10 | 100 % |
| Remote File Include (`TestRemoteFileInclude`) | 4 | 4 | 100 % |
| **TOTAL** | **50** | **47** | **94 %** |

Les 3 payloads non bloqués correspondent à des chemins absolus comme `/etc/passwd` sans séquence de traversal — Flask retourne une redirection HTTP 308 avant que le WAF ne puisse les classifier. Aucun faux positif n'a été observé sur le trafic normal.

---

## 5. Architecture du prototype

### 5.1 Vue d'ensemble

```
      Requête HTTP
           │
           ▼
    ┌─────────────┐
    │  Flask WAF  │   waf_flask_app.py
    │  (port 5000)│
    └──────┬──────┘
           │
    ┌──────▼──────┐
    │  Extraction │   extract_features()
    │  29 features│   re, pandas
    └──────┬──────┘
           │
    ┌──────▼──────┐
    │  MLPClassifier│  waf_model.joblib
    │  (sklearn)  │
    └──────┬──────┘
           │
    ┌──────▼──────────────────┐
    │  prediction == 1 ?      │
    │  OUI → 403 BLOQUÉ       │
    │  NON → Forward backend  │
    └─────────────────────────┘
```

### 5.2 Endpoints disponibles

| Méthode | Endpoint | Description |
|---|---|---|
| GET | `/` | Statut du service |
| GET | `/health` | Santé du service et du modèle |
| GET | `/stats` | Statistiques en temps réel |
| POST | `/predict` | Classification JSON d'une requête |
| POST | `/analyze` | Classification + features détaillées |
| ANY | `/proxy/<path>` | Proxy WAF temps réel |

---

## 6. Discussion et limites

### 6.1 Analyse critique des résultats

Le F1-score de 1.0 obtenu par le MLPClassifier est excellent mais doit être nuancé :

- **Dataset synthétique de petite taille** (100 exemples) : les séparations entre classes sont artificiellement nettes, ce qui favorise les performances parfaites. Sur un dataset réel de plusieurs milliers de requêtes avec des vecteurs d'attaque variés, le score serait probablement plus bas.
- **Overfitting potentiel** : un MLP sur 80 exemples d'entraînement peut mémoriser les données plutôt que généraliser.
- **Distribution calibrée** : les user-agents (sqlmap, Nikto) constituent des features très discriminantes — en leur absence, le recall pourrait chuter.

### 6.2 Limites identifiées

| Limite | Impact | Mitigation possible |
|---|---|---|
| Dataset synthétique | Généralisation non garantie | Utiliser HTTP CSIC 2010, CICIDS |
| Pas d'attaques zero-day | Nouvelles techniques non détectées | Ré-entraînement continu, détection d'anomalies |
| Features simples (URL) | Contournement par obfuscation | Analyse du corps des requêtes, encodages multiples |
| Modèle statique | Dérive temporelle (concept drift) | Mise à jour périodique du modèle |
| Pas d'authentification | Endpoint `/predict` accessible sans protection | API key, mTLS |

### 6.3 Perspectives d'amélioration

1. **Deep Learning** : utiliser des modèles LSTM ou Transformers pour capturer la structure séquentielle des chemins URL.
2. **Features comportementales** : fréquence de requêtes par IP, distribution temporelle, séquence de pages.
3. **Détection d'anomalies non supervisée** : Isolation Forest ou Autoencoder pour détecter des comportements inédits sans labels.
4. **Intégration SIEM** : envoi des alertes vers un système de surveillance centralisé (Elasticsearch, Splunk).
5. **Données réelles** : entraînement sur le dataset HTTP CSIC 2010 ou OWASP WebGoat logs.
6. **Évaluation adversariale** : tester la robustesse contre des attaques d'évasion (obfuscation SQL, encodage Base64).

---

## 7. Conclusion

Ce projet a démontré la faisabilité d'un WAF intelligent basé sur le machine learning. En partant d'un dataset synthétique de 100 requêtes HTTP, nous avons :

- Extrait 29 features comportementales et structurelles des requêtes HTTP.
- Comparé 4 algorithmes de classification : le MLPClassifier s'est imposé avec un F1-score de 1.0.
- Déployé un proxy WAF opérationnel sous Flask, capable d'intercepter, classifier et bloquer des attaques en temps réel.
- Validé l'ensemble par 14 tests automatisés couvrant SQLi, path traversal, scan Nikto, shell upload et trafic normal.

Les limites principales tiennent à la taille et à la nature synthétique du dataset. Les prochaines étapes consistent à évaluer le système sur des données réelles, à intégrer des features comportementales et à explorer les modèles de deep learning pour améliorer la généralisation.

---

## 8. Annexes

### Annexe A — Structure du repository

```
projet-reseau/
├── waf_etapes.ipynb         # Notebook ML complet (exploration → modèle)
├── waf_flask_app.py         # Proxy WAF Flask
├── test_flask_waf.py        # Suite de tests (14 tests)
├── test_owasp_zap.py        # Simulation OWASP ZAP active scanner (50 payloads)
├── waf_model.joblib         # Modèle MLPClassifier exporté
├── donnees_nettoyees.csv    # Dataset nettoyé après feature engineering
├── setup_env.ps1            # Script d'installation Python 3.12
├── plan_travail.md          # Plan de travail 4 semaines
├── plan_rapport.md          # Structure du rapport
├── plan_presentation.md     # Structure des slides
└── discussion_limites.md    # Analyse critique
```

### Annexe B — Extrait de features pour une requête SQLi

```json
{
  "request_path":   "/admin/users.php?id=1 UNION SELECT null,version()--",
  "user_agent":     "sqlmap/1.6.10",
  "path_length":    52,
  "has_union":      1,
  "has_select":     1,
  "has_admin":      1,
  "special_char_count": 2,
  "user_agent_sqlmap":  1,
  "method_GET":     1,
  "status_200":     1
}
→ Prédiction : MALICIEUX (probabilité = 100.0%)
```

### Annexe C — Métriques clés

| Métrique | Valeur | Formule |
|---|---|---|
| Accuracy | 1.000 | (TP+TN)/(TP+TN+FP+FN) |
| Precision | 1.000 | TP/(TP+FP) |
| Recall | 1.000 | TP/(TP+FN) |
| F1-score | 1.000 | 2·P·R/(P+R) |
| Faux positifs | 0 | Trafic légitime bloqué |
| Faux négatifs | 0 | Attaques non détectées |

---

## 9. Bibliographie

[1] OWASP Foundation. *OWASP Top Ten Web Application Security Risks*. https://owasp.org/www-project-top-ten/, 2021.

[2] Verizon. *Data Breach Investigations Report (DBIR)*. Verizon Business, 2024.

[3] Torrano-Gimenez, C., Perez-Villegas, A., Alvarez, G. *HTTP CSIC 2010 Dataset for Anomalous Web Requests*. Spanish National Research Council (CSIC), 2010.

[4] Sharafaldin, I., Habibi Lashkari, A., Ghorbani, A. A. *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization*. Proceedings of the 4th International Conference on Information Systems Security and Privacy (ICISSP), 2018.

[5] Pedregosa, F. et al. *Scikit-learn: Machine Learning in Python*. Journal of Machine Learning Research, 12, 2825-2830, 2011.

[6] Breiman, L. *Random Forests*. Machine Learning, 45(1), 5-32, 2001.

[7] Cortes, C., Vapnik, V. *Support-Vector Networks*. Machine Learning, 20(3), 273-297, 1995.

[8] Rumelhart, D. E., Hinton, G. E., Williams, R. J. *Learning representations by back-propagating errors*. Nature, 323, 533-536, 1986.

[9] Sharma, R., Singh, A. *Machine Learning based Web Application Firewall for Detection of SQL Injection Attacks*. International Journal of Computer Applications, 2023.

[10] Palczewska, A., Palczewski, J. et al. *Interpreting Random Forest classification models using a feature contribution method*. Springer, 2014.

[11] ModSecurity. *OWASP ModSecurity Core Rule Set (CRS)*. https://owasp.org/www-project-modsecurity-core-rule-set/, 2023.

[12] Amazon Web Services. *AWS WAF - Web Application Firewall*. https://aws.amazon.com/waf/, 2024.

---

*Rapport genere le 7 avril 2026 — projet-reseau / dica11*
