# Plan de travail du projet WAF intelligent

## Semaine 1 : Revue et préparation
1. Revue de littérature sur les attaques web et les WAF existants
2. Étude comparative des solutions (ModSecurity, AWS WAF, etc.)
3. Sélection du dataset (ex : HTTP CSIC 2010, OWASP Web Attack)
4. Préparation de l’environnement de travail (Python, Jupyter, GitHub)

## Semaine 2 : Données et modélisation
1. Nettoyage et prétraitement du dataset
2. Extraction des caractéristiques pertinentes (features engineering)
3. Analyse exploratoire des données (statistiques, visualisations)
4. Séparation du dataset (train/test)
5. Entraînement de plusieurs modèles de machine learning (Logistic Regression, Random Forest, SVM, Neural Network)
6. Sélection du meilleur modèle selon les métriques (accuracy, recall, etc.)

## Semaine 3 : Développement du prototype
1. Développement d’un proxy WAF avec Flask
2. Intégration du modèle de machine learning dans le proxy
3. Interception et analyse des requêtes HTTP
4. Classification en temps réel (normal ou attaque)
5. Blocage ou autorisation des requêtes selon la prédiction

## Semaine 4 : Évaluation et rapport
1. Tests d’attaques avec des outils comme OWASP ZAP ou Burp Suite
2. Évaluation des performances (accuracy, recall, F1-score, taux de faux positifs)
3. Analyse des résultats et des limites
4. Rédaction du rapport scientifique (10 à 15 pages)
5. Préparation de la présentation (10 slides)
