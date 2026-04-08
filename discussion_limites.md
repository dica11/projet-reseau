# Discussion, limites et perspectives

## Limites du modèle
- Dépendance à la qualité et à la diversité du dataset (risque de surapprentissage)
- Difficulté à détecter des attaques zero-day ou très sophistiquées
- Possibles biais si certaines attaques sont sous-représentées
- Modèle sensible à l’évolution des techniques d’attaque

## Robustesse et généralisabilité
- Les modèles ML peuvent être trompés par des attaques d’évasion (adversarial)
- Les features extraites sont simples : un attaquant peut les contourner
- Nécessité de mettre à jour régulièrement le modèle et les features

## Perspectives d’amélioration
- Tester des modèles de deep learning (LSTM, Transformers) pour mieux capter la structure des requêtes
- Ajouter des features comportementales (fréquence, séquence de requêtes, etc.)
- Intégrer un système de détection d’anomalies non supervisé
- Coupler le WAF à un SIEM pour une supervision centralisée
- Automatiser la collecte de nouveaux exemples pour améliorer le modèle
