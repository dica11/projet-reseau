# Plan de travail du projet WAF intelligent

## Semaine 1 : Revue et prparation
1. Revue de littrature sur les attaques web et les WAF existants
2. tude comparative des solutions (ModSecurity, AWS WAF, etc.)
3. Slection du dataset (ex : HTTP CSIC 2010, OWASP Web Attack)
4. Prparation de lenvironnement de travail (Python, Jupyter, GitHub)

## Semaine 2 : Donnes et modlisation
1. Nettoyage et prtraitement du dataset
2. Extraction des caractristiques pertinentes (features engineering)
3. Analyse exploratoire des donnes (statistiques, visualisations)
4. Sparation du dataset (train/test)
5. Entranement de plusieurs modles de machine learning (Logistic Regression, Random Forest, SVM, Neural Network)
6. Slection du meilleur modle selon les mtriques (accuracy, recall, etc.)

## Semaine 3 : Dveloppement du prototype
1. Dveloppement dun proxy WAF avec Flask
2. Intgration du modle de machine learning dans le proxy
3. Interception et analyse des requtes HTTP
4. Classification en temps rel (normal ou attaque)
5. Blocage ou autorisation des requtes selon la prdiction

## Semaine 4 : valuation et rapport
1. Tests dattaques avec des outils comme OWASP ZAP ou Burp Suite
2. valuation des performances (accuracy, recall, F1-score, taux de faux positifs)
3. Analyse des rsultats et des limites
4. Rdaction du rapport scientifique (10  15 pages)
5. Prparation de la prsentation (10 slides)

