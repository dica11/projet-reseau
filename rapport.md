# Rapport scientifique
# WAF intelligent bas sur le Machine Learning
## Dtection automatique de requtes web malicieuses par apprentissage automatique

**Auteur :** quipe projet-reseau  
**Date :** Avril 2026  
**Repository :** https://github.com/dica11/projet-reseau

---

## Rsum

Ce rapport prsente la conception, l'implmentation et l'valuation d'un Web Application Firewall (WAF) intelligent fond sur des techniques de machine learning. L'objectif est de dpasser les limites des WAF bass sur des rgles statiques en s'appuyant sur un modle d'apprentissage automatique capable de classer en temps rel les requtes HTTP comme normales ou malicieuses. Quatre algorithmes ont t compars : rgression logistique, fort alatoire, SVM et rseau de neurones. Le meilleur modle (MLPClassifier) atteint un F1-score de 1.0 sur l'ensemble de test. Un prototype complet sous Flask a t dploy et valid par une suite de 14 tests automatiss (100 % de russite).

---

## 1. Introduction

### 1.1 Contexte et enjeux

La scurit des applications web est aujourd'hui un enjeu critique. Selon le rapport Verizon Data Breach Investigations (2024), plus de 40 % des violations de donnes impliquent des applications web. Les attaques les plus frquentes  injections SQL, traverses de rpertoires, scans automatiques  ciblent directement les serveurs applicatifs et peuvent conduire  l'exfiltration de donnes sensibles, la prise de contrle de systmes ou l'interruption de service.

Les Web Application Firewalls (WAF) constituent la dfense de premire ligne. Cependant, les solutions classiques (ModSecurity, AWS WAF, etc.) reposent sur des signatures statiques ou des listes de rgles maintenues manuellement. Cette approche prsente deux limites fondamentales :

1. **Ractivit faible** : un nouveau vecteur d'attaque non rpertori n'est pas dtect avant la mise  jour des rgles.
2. **Taux de faux positifs lev** : des rgles trop gnriques bloquent du trafic lgitime, nuisant  l'exprience utilisateur.

### 1.2 Problmatique

Comment concevoir un WAF capable d'apprendre automatiquement les caractristiques distinguant une requte normale d'une requte malicieuse, sans ncessiter de mise  jour manuelle des rgles ?

### 1.3 Objectifs du projet

- Construire un dataset synthtique reprsentatif du trafic web rel et malicieux.
- Extraire des features pertinentes  partir des mtadonnes HTTP.
- Entraner et comparer plusieurs modles de machine learning.
- Dployer le meilleur modle dans un proxy WAF oprationnel (Flask).
- Valider le systme par des tests automatiss couvrant des scenarios d'attaque rels.

---

## 2. tat de l'art

### 2.1 Principales attaques web

| Attaque | Description | Exemple |
|---|---|---|
| **SQL Injection (SQLi)** | Injection de code SQL dans les paramtres d'URL ou de formulaire | `?id=1 UNION SELECT null,version()--` |
| **Path Traversal** | Navigation hors du rpertoire web autoris | `/../../../../etc/passwd` |
| **XSS (Cross-Site Scripting)** | Injection de code JavaScript dans des rponses web | `<script>alert(1)</script>` |
| **Scan automatique** | Reconnaissance de vulnrabilits par des outils (Nikto, sqlmap) | User-Agent: `Nikto/2.1.6` |
| **Shell upload** | Dpt d'un fichier excutable malicieux via une interface d'upload | `/upload.php?file=shell.php` |

### 2.2 WAF traditionnels

Les solutions commerciales et open-source reposent principalement sur :

- **Signatures statiques** (ModSecurity avec le Core Rule Set OWASP) : efficaces contre les attaques connues, contournables par obfuscation.
- **Listes noires/blanches** d'IP ou de user-agents : maintenance coteuse, peu scalable.
- **Analyse heuristique** : dtection de patterns suspects, source de nombreux faux positifs.

**Limites identifies :** rigidit, manque d'adaptation aux nouvelles attaques, difficult  traiter des volumes importants de trafic htrogne.

### 2.3 Apports du Machine Learning

L'apprentissage automatique permet d'apprendre des reprsentations statistiques du trafic normal et anormal, offrant :

- **Gnralisation** : dtection d'attaques indites prsentant des patterns similaires aux attaques connues.
- **Adaptabilit** : le modle peut tre r-entran sur de nouvelles donnes.
- **Classification probabiliste** : fourniture d'un score de confiance, permettant de graduer la rponse.

Des travaux rcents (Sharma & Singh, 2023 ; Nguyen et al., 2024) montrent que les approches Random Forest et Deep Learning surpassent significativement les rgles statiques sur des jeux de donnes rels (CICIDS, HTTP CSIC 2010).

---

## 3. Mthodologie

### 3.1 Dataset synthtique

En l'absence de donnes relles disponibles dans le cadre de ce projet, un dataset synthtique a t gnr pour simuler un trafic web raliste.

**Composition :** 100 requtes HTTP, dont 21 malicieuses (21 %).

**Requtes normales (79 %)**  Chemins : `/`, `/index.html`, `/login`, `/products`, `/api/data`, `/dashboard`

**Requtes malicieuses (21 %)**  Incluant :
- Injections SQL : `/admin/users.php?id=1 UNION SELECT null,null,version()--`
- Path traversal : `/../../../../windows/system32/cmd.exe`
- Exploitation de fichiers systme : `/etc/passwd`
- Accs phpmyadmin : `/phpmyadmin/index.php?pma_username=root`
- Webshells : `/shell.php`, `/upload.php?file=evil.php`
- Scan WordPress : `/wp-admin/admin-ajax.php`

**User-agents** : navigateurs lgitimes, curl, Python-requests, Nikto, sqlmap.

### 3.2 Extraction de features (Feature Engineering)

29 features binaires ou numriques ont t extraites de chaque requte HTTP :

| Catgorie | Features | Nombre |
|---|---|---|
| Longueur et structure du chemin | `path_length`, `param_count` | 2 |
| Mots-cls suspects | `has_select`, `has_union`, `has_script`, `has_slash_slash`, `has_or_1_1`, `has_cmd_dot_exe`, `has_passwd`, `has_shell`, `has_upload`, `has_phpmyadmin`, `has_admin` | 11 |
| Caractres spciaux | `special_char_count` | 1 |
| Mthode HTTP (one-hot) | `method_GET/POST/PUT/DELETE` | 4 |
| Code statut HTTP (one-hot) | `status_200/301/400/401/403/404/500` | 7 |
| User-agent suspect | `user_agent_sqlmap`, `user_agent_nikto`, `user_agent_curl`, `user_agent_python` | 4 |
| **Total** | | **29** |

### 3.3 Modles de machine learning

Quatre algorithmes de classification supervise ont t valus :

| Modle | Hyperparamtres | Justification |
|---|---|---|
| **Logistic Regression** | `max_iter=1000` | Baseline interprtable |
| **Random Forest** | `n_estimators=100, random_state=42` | Robuste, gre les features non linaires |
| **SVM** | `kernel=rbf, random_state=42` | Efficace sur espaces de haute dimension |
| **Neural Network (MLP)** | `max_iter=500, random_state=42` | Capture les interactions complexes |

**Sparation train/test :** 80/20 stratifie (80 exemples d'entranement, 20 de test), `random_state=42`.

---

## 4. Rsultats exprimentaux

### 4.1 Performances compares

| Modle | Accuracy | Precision | Recall | F1-score |
|---|---|---|---|---|
| **Neural Network (MLP)** | **1.000** | **1.000** | **1.000** | **1.000** |
| Logistic Regression | 0.900 | 1.000 | 0.500 | 0.667 |
| Random Forest | 0.900 | 1.000 | 0.500 | 0.667 |
| SVM | 0.900 | 1.000 | 0.500 | 0.667 |

Le **MLPClassifier** (rseau de neurones multicouche) domine nettement avec un F1-score parfait de 1.0, contre 0.667 pour les trois autres modles.

L'cart s'explique par le **recall** : le MLP dtecte 100 % des requtes malicieuses, tandis que les autres modles n'en dtectent que 50 % (recall = 0.5). La precision tant de 1.0 pour tous, il n'y a aucun faux positif dans les quatre cas.

### 4.2 Matrice de confusion  Neural Network (meilleur modle)

```
                Prdit NORMAL   Prdit MALICIEUX
Rel NORMAL          16               0           0 faux positifs
Rel MALICIEUX        0               4           0 faux ngatifs
```

**Interprtation :**
- **16 vrais ngatifs** : toutes les requtes normales correctement autorises.
- **4 vrais positifs** : toutes les requtes malicieuses correctement dtectes.
- **0 faux positifs** : aucun blocage abusif de trafic lgitime.
- **0 faux ngatifs** : aucune attaque non dtecte.

### 4.3 Tests d'attaque sur le proxy WAF

La suite de 14 tests automatiss (`test_flask_waf.py`) valide le comportement du proxy en conditions relles :

| Test | Rsultat | Probabilit malicieuse |
|---|---|---|
| Requte GET normale `/products` | AUTORIS | 2.1% |
| SQLi `UNION SELECT` (sqlmap UA) |  BLOQU (HTTP 403) | 100.0% |
| Path traversal `/../../../../etc/passwd` |  BLOQU | 100.0% |
| Scan Nikto `/phpmyadmin/index.php` | BLOQU | 98.9% |
| Shell upload `/upload.php?file=shell.php` |  BLOQU | 100.0% |
| `/proxy` SQLi (trafic HTTP rel) |  BLOQU (HTTP 403) | 100.0% |
| `/proxy` requte normale |  TRANSFR (HTTP 200) | 0.1% |

**Rsultat global : 14/14 tests russis (100 %)**

### 4.4 Simulation OWASP ZAP Active Scanner

Un second script (`test_owasp_zap.py`) reproduit les payloads rels de l'active scanner OWASP ZAP en les envoyant sur le proxy WAF. Les payloads proviennent directement du code source des modules ZAP (`zap-extensions/addOns/ascanrules`).

| Catgorie ZAP | Payloads | Bloqus | Taux |
|---|---|---|---|
| SQL Injection (`TestSQLInjection`) | 15 | 15 | 100 % |
| Path Traversal (`TestPathTraversal`) | 12 | 9 | 75 % |
| XSS (`TestCrossSiteScripting`) | 9 | 9 | 100 % |
| Command Injection (`TestRemoteOSCommandInjection`) | 10 | 10 | 100 % |
| Remote File Include (`TestRemoteFileInclude`) | 4 | 4 | 100 % |
| **TOTAL** | **50** | **47** | **94 %** |

Les 3 payloads non bloqus correspondent  des chemins absolus comme `/etc/passwd` sans squence de traversal  Flask retourne une redirection HTTP 308 avant que le WAF ne puisse les classifier. Aucun faux positif n'a t observ sur le trafic normal.

---

## 5. Architecture du prototype

### 5.1 Vue d'ensemble

```
      Requte HTTP
           
           
    
      Flask WAF     waf_flask_app.py
      (port 5000)
    
           
    
      Extraction    extract_features()
      29 features   re, pandas
    
           
    
      MLPClassifier  waf_model.joblib
      (sklearn)  
    
           
    
      prediction == 1 ?      
      OUI  403 BLOQU       
      NON  Forward backend  
    
```

### 5.2 Endpoints disponibles

| Mthode | Endpoint | Description |
|---|---|---|
| GET | `/` | Statut du service |
| GET | `/health` | Sant du service et du modle |
| GET | `/stats` | Statistiques en temps rel |
| POST | `/predict` | Classification JSON d'une requte |
| POST | `/analyze` | Classification + features dtailles |
| ANY | `/proxy/<path>` | Proxy WAF temps rel |

---

## 6. Discussion et limites

### 6.1 Analyse critique des rsultats

Le F1-score de 1.0 obtenu par le MLPClassifier est excellent mais doit tre nuanc :

- **Dataset synthtique de petite taille** (100 exemples) : les sparations entre classes sont artificiellement nettes, ce qui favorise les performances parfaites. Sur un dataset rel de plusieurs milliers de requtes avec des vecteurs d'attaque varis, le score serait probablement plus bas.
- **Overfitting potentiel** : un MLP sur 80 exemples d'entranement peut mmoriser les donnes plutt que gnraliser.
- **Distribution calibre** : les user-agents (sqlmap, Nikto) constituent des features trs discriminantes  en leur absence, le recall pourrait chuter.

### 6.2 Limites identifies

| Limite | Impact | Mitigation possible |
|---|---|---|
| Dataset synthtique | Gnralisation non garantie | Utiliser HTTP CSIC 2010, CICIDS |
| Pas d'attaques zero-day | Nouvelles techniques non dtectes | R-entranement continu, dtection d'anomalies |
| Features simples (URL) | Contournement par obfuscation | Analyse du corps des requtes, encodages multiples |
| Modle statique | Drive temporelle (concept drift) | Mise  jour priodique du modle |
| Pas d'authentification | Endpoint `/predict` accessible sans protection | API key, mTLS |

### 6.3 Perspectives d'amlioration

1. **Deep Learning** : utiliser des modles LSTM ou Transformers pour capturer la structure squentielle des chemins URL.
2. **Features comportementales** : frquence de requtes par IP, distribution temporelle, squence de pages.
3. **Dtection d'anomalies non supervise** : Isolation Forest ou Autoencoder pour dtecter des comportements indits sans labels.
4. **Intgration SIEM** : envoi des alertes vers un systme de surveillance centralis (Elasticsearch, Splunk).
5. **Donnes relles** : entranement sur le dataset HTTP CSIC 2010 ou OWASP WebGoat logs.
6. **valuation adversariale** : tester la robustesse contre des attaques d'vasion (obfuscation SQL, encodage Base64).

---

## 7. Conclusion

Ce projet a dmontr la faisabilit d'un WAF intelligent bas sur le machine learning. En partant d'un dataset synthtique de 100 requtes HTTP, nous avons :

- Extrait 29 features comportementales et structurelles des requtes HTTP.
- Compar 4 algorithmes de classification : le MLPClassifier s'est impos avec un F1-score de 1.0.
- Dploy un proxy WAF oprationnel sous Flask, capable d'intercepter, classifier et bloquer des attaques en temps rel.
- Valid l'ensemble par 14 tests automatiss couvrant SQLi, path traversal, scan Nikto, shell upload et trafic normal.

Les limites principales tiennent  la taille et  la nature synthtique du dataset. Les prochaines tapes consistent  valuer le systme sur des donnes relles,  intgrer des features comportementales et  explorer les modles de deep learning pour amliorer la gnralisation.

---

## 8. Annexes

### Annexe A  Structure du repository

```
projet-reseau/
 waf_etapes.ipynb         # Notebook ML complet (exploration  modle)
 waf_flask_app.py         # Proxy WAF Flask
 test_flask_waf.py        # Suite de tests (14 tests)
 test_owasp_zap.py        # Simulation OWASP ZAP active scanner (50 payloads)
 waf_model.joblib         # Modle MLPClassifier export
 donnees_nettoyees.csv    # Dataset nettoy aprs feature engineering
 setup_env.ps1            # Script d'installation Python 3.12
 plan_travail.md          # Plan de travail 4 semaines
 plan_rapport.md          # Structure du rapport
 plan_presentation.md     # Structure des slides
 discussion_limites.md    # Analyse critique
```

### Annexe B  Extrait de features pour une requte SQLi

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
 Prdiction : MALICIEUX (probabilit = 100.0%)
```

### Annexe C  Mtriques cls

| Mtrique | Valeur | Formule |
|---|---|---|
| Accuracy | 1.000 | (TP+TN)/(TP+TN+FP+FN) |
| Precision | 1.000 | TP/(TP+FP) |
| Recall | 1.000 | TP/(TP+FN) |
| F1-score | 1.000 | 2PR/(P+R) |
| Faux positifs | 0 | Trafic lgitime bloqu |
| Faux ngatifs | 0 | Attaques non dtectes |

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

*Rapport genere le 7 avril 2026  projet-reseau / dica11*

