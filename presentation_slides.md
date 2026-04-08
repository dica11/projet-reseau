# Présentation — WAF intelligent basé sur le Machine Learning
## 10 slides — Projet réseau, Avril 2026

---

## Slide 1 — Titre

**WAF intelligent basé sur le Machine Learning**
*Détection automatique de requêtes web malicieuses*

- **Cours :** Sécurité des réseaux
- **Équipe :** projet-reseau
- **Date :** Avril 2026
- **GitHub :** github.com/dica11/projet-reseau

---

## Slide 2 — Contexte et enjeux

**Pourquoi sécuriser les applications web ?**

- **+40 %** des violations de données impliquent des applications web (Verizon DBIR 2024)
- Attaques les plus fréquentes :
  - Injection SQL (SQLi)
  - Traversée de répertoires
  - Scans automatiques (Nikto, sqlmap)
  - Dépôt de webshells
- Impact : vol de données, prise de contrôle, interruption de service

> *« Toute application exposée sur Internet est une cible potentielle. »*

---

## Slide 3 — Limites des WAF classiques

**Pourquoi les solutions actuelles ne suffisent pas ?**

| Approche classique | Limite |
|---|---|
| Signatures statiques (ModSecurity) | Contournables par obfuscation |
| Listes noires d'IP | Maintenance manuelle, non scalable |
| Règles OWASP CRS | Taux de faux positifs élevé |

**Problème central :**
> Un WAF basé sur des règles ne peut pas détecter ce qu'il n'a jamais vu.

**Notre solution :** apprendre automatiquement les patterns du trafic malicieux.

---

## Slide 4 — Objectifs et approche

**Un WAF qui apprend**

```
Requête HTTP
     │
     ▼
Extraction de 29 features
     │
     ▼
Modèle ML (entraîné)
     │
  ┌──┴──┐
NORMAL  MALICIEUX
  │         │
Transférer  Bloquer (403)
```

**Objectifs :**
1. Classifier des requêtes HTTP en temps réel
2. Comparer 4 algorithmes ML
3. Déployer un proxy WAF opérationnel (Flask)

---

## Slide 5 — Données et features

**Dataset synthétique — 100 requêtes HTTP**

| Classe | Nombre | Exemples |
|---|---|---|
| Normales | 79 (79 %) | `/products`, `/login`, `/dashboard` |
| Malicieuses | 21 (21 %) | SQLi, path traversal, Nikto, sqlmap |

**29 features extraites de chaque requête :**

- `path_length`, `param_count` — longueur et structure
- `has_select`, `has_union`, `has_admin`... — 11 mots-clés suspects
- `special_char_count` — caractères dangereux `;=(){}[]<>`
- `method_GET/POST/PUT/DELETE` — méthode HTTP (one-hot)
- `status_200/301/.../500` — code de réponse (one-hot)
- `user_agent_sqlmap`, `user_agent_nikto`... — user-agents suspects

---

## Slide 6 — Modèles et résultats

**Comparaison de 4 algorithmes (split 80/20 stratifié)**

| Modèle | Accuracy | Precision | Recall | **F1** |
|---|---|---|---|---|
| ** Neural Network (MLP)** | **1.000** | **1.000** | **1.000** | **1.000** |
| Logistic Regression | 0.900 | 1.000 | 0.500 | 0.667 |
| Random Forest | 0.900 | 1.000 | 0.500 | 0.667 |
| SVM | 0.900 | 1.000 | 0.500 | 0.667 |

**Différence clé : le Recall**
- MLP : détecte **100 %** des attaques
- Autres : manquent **50 %** des attaques (faux négatifs)

---

## Slide 7 — Matrice de confusion

**Meilleur modèle : MLPClassifier**

```
                  Prédit NORMAL   Prédit MALICIEUX
Réel NORMAL            16               0
Réel MALICIEUX          0               4
```

**Résultats sur 20 requêtes de test :**

| | Valeur |
|---|---|
|  Vrais positifs (attaques détectées) | 4 / 4 |
|  Vrais négatifs (normales autorisées) | 16 / 16 |
|  Faux positifs (blocage abusif) | **0** |
|  Faux négatifs (attaques manquées) | **0** |

---

## Slide 8 — Prototype WAF Flask

**Architecture du proxy opérationnel**

**5 endpoints :**

| Endpoint | Rôle |
|---|---|
| `GET /health` | Santé du service |
| `GET /stats` | Statistiques temps réel |
| `POST /predict` | Classification JSON |
| `POST /analyze` | Classification + 29 features |
| `ANY /proxy/<path>` | **Proxy WAF en temps réel** |

**Démonstration — SQLi bloquée en temps réel :**
```
GET /proxy/admin/users.php?id=1+UNION+SELECT+null,version()--
User-Agent: sqlmap/1.6.10

→ HTTP 403 | Probabilité malicieuse : 100.0%
→ BLOQUÉ par le WAF
```

**Suite de tests : 14/14 réussis (100 %)**

**Simulation OWASP ZAP Active Scanner (`test_owasp_zap.py`) :**

| Catégorie | Bloqués |
|---|---|
| SQL Injection (15 payloads) | 15/15 — 100 % |
| XSS (9 payloads) | 9/9 — 100 % |
| Command Injection (10 payloads) | 10/10 — 100 % |
| Remote File Include (4 payloads) | 4/4 — 100 % |
| Path Traversal (12 payloads) | 9/12 — 75 % |
| **Total** | **47/50 — 94 %** |

0 faux positifs sur trafic normal.

---

## Slide 9 — Limites et perspectives

**Ce que le modèle ne fait pas (encore)**

| Limite | Impact | Solution envisagée |
|---|---|---|
| Dataset synthétique | Généralisation incertaine | HTTP CSIC 2010, CICIDS |
| Pas d'attaques zero-day | Nouvelles techniques non détectées | Détection d'anomalies (Isolation Forest) |
| Features URL uniquement | Obfuscation possible | Analyse du corps des requêtes |
| Modèle statique | Dégradation dans le temps | Ré-entraînement automatique |

**Perspectives :**
-  LSTM / Transformers pour analyser la structure séquentielle des URL
-  Features comportementales (fréquence, trajectoire de navigation)
-  Intégration SIEM pour supervision centralisée
-  Tests d'évasion adversariale (robustesse)

---

## Slide 10 — Conclusion

**Bilan du projet**

 **Semaine 1** — Environnement Python 3.12, GitHub, revue de littérature  
 **Semaine 2** — Dataset, 29 features, 4 modèles, MLPClassifier F1=1.0  
 **Semaine 3** — Proxy WAF Flask, 5 endpoints, proxy temps réel  
 **Semaine 4** — Tests (14/14), simulation OWASP ZAP (94%), rapport, présentation  

**Ce qu'on a prouvé :**
> Un modèle ML peut classifier du trafic HTTP malicieux avec une précision parfaite sur des données synthétiques et bloquer les attaques en temps réel via un proxy Flask.

**Prochaine étape :**
> Évaluation sur des données de production réelles et intégration dans une infrastructure de sécurité existante.

---

**Questions ?**

*Merci — Code disponible sur github.com/dica11/projet-reseau*
