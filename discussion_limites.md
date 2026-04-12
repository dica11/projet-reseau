# Discussion, limites et perspectives

## Limites du modle
- Dpendance  la qualit et  la diversit du dataset (risque de surapprentissage)
- Difficult  dtecter des attaques zero-day ou trs sophistiques
- Possibles biais si certaines attaques sont sous-reprsentes
- Modle sensible  lvolution des techniques dattaque

## Robustesse et gnralisabilit
- Les modles ML peuvent tre tromps par des attaques dvasion (adversarial)
- Les features extraites sont simples: un attaquant peut les contourner
- Ncessit de mettre  jour rgulirement le modle et les features

## Perspectives damlioration
- Tester des modles de deep learning (LSTM, Transformers) pour mieux capter la structure des requtes
- Ajouter des features comportementales (frquence, squence de requtes, etc.)
- Intgrer un systme de dtection danomalies non supervis
- Coupler le WAF  un SIEM pour une supervision centralise
- Automatiser la collecte de nouveaux exemples pour amliorer le modle

