# Prsentation  WAF intelligent bas sur le Machine Learning
## 10 slides  Projet rseau, Avril 2026

---

## Slide 1  Titre

**WAF intelligent bas sur le Machine Learning**
*Dtection automatique de requtes web malicieuses*

- **Cours :** Scurit des rseaux
- **quipe :** projet-reseau
- **Date :** Avril 2026
- **GitHub :** github.com/dica11/projet-reseau

---

## Slide 2  Contexte et enjeux

**Pourquoi scuriser les applications web ?**

- **+40 %** des violations de donnes impliquent des applications web (Verizon DBIR 2024)
- Attaques les plus frquentes :
  - Injection SQL (SQLi)
  - Traverse de rpertoires
  - Scans automatiques (Nikto, sqlmap)
  - Dpt de webshells
- Impact : vol de donnes, prise de contrle, interruption de service

> * Toute application expose sur Internet est une cible potentielle. *

---

## Slide 3  Limites des WAF classiques

**Pourquoi les solutions actuelles ne suffisent pas ?**

| Approche classique | Limite |
|---|---|
| Signatures statiques (ModSecurity) | Contournables par obfuscation |
| Listes noires d'IP | Maintenance manuelle, non scalable |
| Rgles OWASP CRS | Taux de faux positifs lev |

**Problme central :**
> Un WAF bas sur des rgles ne peut pas dtecter ce qu'il n'a jamais vu.

**Notre solution :** apprendre automatiquement les patterns du trafic malicieux.

---

## Slide 4  Objectifs et approche

**Un WAF qui apprend**

```
Requte HTTP
     
     
Extraction de 29 features
     
     
Modle ML (entran)
     
  
NORMAL  MALICIEUX
           
Transfrer  Bloquer (403)
```

**Objectifs :**
1. Classifier des requtes HTTP en temps rel
2. Comparer 4 algorithmes ML
3. Dployer un proxy WAF oprationnel (Flask)

---

## Slide 5  Donnes et features

**Dataset synthtique  100 requtes HTTP**

| Classe | Nombre | Exemples |
|---|---|---|
| Normales | 79 (79 %) | `/products`, `/login`, `/dashboard` |
| Malicieuses | 21 (21 %) | SQLi, path traversal, Nikto, sqlmap |

**29 features extraites de chaque requte :**

- `path_length`, `param_count`  longueur et structure
- `has_select`, `has_union`, `has_admin`...  11 mots-cls suspects
- `special_char_count`  caractres dangereux `;=(){}[]<>`
- `method_GET/POST/PUT/DELETE`  mthode HTTP (one-hot)
- `status_200/301/.../500`  code de rponse (one-hot)
- `user_agent_sqlmap`, `user_agent_nikto`...  user-agents suspects

---

## Slide 6  Modles et rsultats

**Comparaison de 4 algorithmes (split 80/20 stratifi)**

| Modle | Accuracy | Precision | Recall | **F1** |
|---|---|---|---|---|
| ** Neural Network (MLP)** | **1.000** | **1.000** | **1.000** | **1.000** |
| Logistic Regression | 0.900 | 1.000 | 0.500 | 0.667 |
| Random Forest | 0.900 | 1.000 | 0.500 | 0.667 |
| SVM | 0.900 | 1.000 | 0.500 | 0.667 |

**Diffrence cl : le Recall**
- MLP : dtecte **100 %** des attaques
- Autres : manquent **50 %** des attaques (faux ngatifs)

---

## Slide 7  Matrice de confusion

**Meilleur modle : MLPClassifier**

```
                  Prdit NORMAL   Prdit MALICIEUX
Rel NORMAL            16               0
Rel MALICIEUX          0               4
```

**Rsultats sur 20 requtes de test :**

| | Valeur |
|---|---|
|  Vrais positifs (attaques dtectes) | 4 / 4 |
|  Vrais ngatifs (normales autorises) | 16 / 16 |
|  Faux positifs (blocage abusif) | **0** |
|  Faux ngatifs (attaques manques) | **0** |

---

## Slide 8  Prototype WAF Flask

**Architecture du proxy oprationnel**

**5 endpoints :**

| Endpoint | Rle |
|---|---|
| `GET /health` | Sant du service |
| `GET /stats` | Statistiques temps rel |
| `POST /predict` | Classification JSON |
| `POST /analyze` | Classification + 29 features |
| `ANY /proxy/<path>` | **Proxy WAF en temps rel** |

**Dmonstration  SQLi bloque en temps rel :**
```
GET /proxy/admin/users.php?id=1+UNION+SELECT+null,version()--
User-Agent: sqlmap/1.6.10

 HTTP 403 | Probabilit malicieuse : 100.0%
 BLOQU par le WAF
```

**Suite de tests : 14/14 russis (100 %)**

**Simulation OWASP ZAP Active Scanner (`test_owasp_zap.py`) :**

| Catgorie | Bloqus |
|---|---|
| SQL Injection (15 payloads) | 15/15  100 % |
| XSS (9 payloads) | 9/9  100 % |
| Command Injection (10 payloads) | 10/10  100 % |
| Remote File Include (4 payloads) | 4/4  100 % |
| Path Traversal (12 payloads) | 9/12  75 % |
| **Total** | **47/50  94 %** |

0 faux positifs sur trafic normal.

---

## Slide 9  Limites et perspectives

**Ce que le modle ne fait pas (encore)**

| Limite | Impact | Solution envisage |
|---|---|---|
| Dataset synthtique | Gnralisation incertaine | HTTP CSIC 2010, CICIDS |
| Pas d'attaques zero-day | Nouvelles techniques non dtectes | Dtection d'anomalies (Isolation Forest) |
| Features URL uniquement | Obfuscation possible | Analyse du corps des requtes |
| Modle statique | Dgradation dans le temps | R-entranement automatique |

**Perspectives :**
-  LSTM / Transformers pour analyser la structure squentielle des URL
-  Features comportementales (frquence, trajectoire de navigation)
-  Intgration SIEM pour supervision centralise
-  Tests d'vasion adversariale (robustesse)

---

## Slide 10  Conclusion

**Bilan du projet**

 **Semaine 1**  Environnement Python 3.12, GitHub, revue de littrature  
 **Semaine 2**  Dataset, 29 features, 4 modles, MLPClassifier F1=1.0  
 **Semaine 3**  Proxy WAF Flask, 5 endpoints, proxy temps rel  
 **Semaine 4**  Tests (14/14), simulation OWASP ZAP (94%), rapport, prsentation  

**Ce qu'on a prouv :**
> Un modle ML peut classifier du trafic HTTP malicieux avec une prcision parfaite sur des donnes synthtiques et bloquer les attaques en temps rel via un proxy Flask.

**Prochaine tape :**
> valuation sur des donnes de production relles et intgration dans une infrastructure de scurit existante.

---

**Questions ?**

*Merci  Code disponible sur github.com/dica11/projet-reseau*

