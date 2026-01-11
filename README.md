# VulnAPI

API volontairement vulnérable pour l'apprentissage de la sécurité des APIs.

## Avertissement

Ce logiciel contient des vulnérabilités **intentionnelles** à des fins éducatives.
**Ne jamais déployer en production.**

## Objectifs

- Comprendre les vulnérabilités OWASP API Security Top 10
- Pratiquer l'exploitation dans un environnement contrôlé
- Comparer les vecteurs d'attaque REST vs GraphQL
- Apprendre à sécuriser ses APIs

## Structure du projet

```
vulnapi/
├── specs/                    # Contrat API commun (OpenAPI, tests)
├── implementations/
│   └── python-fastapi/       # Implémentation de référence
└── PROJECT_SPEC.md           # Spécification complète du projet
```

## Démarrage rapide

```bash
cd implementations/python-fastapi

# Créer l'environnement virtuel
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Installer les dépendances
pip install -r requirements.txt

# Lancer l'API
uvicorn app.main:app --reload
```

L'API sera disponible sur `http://localhost:8000`

## Phases du projet

| Phase | Description | Statut |
|-------|-------------|--------|
| 1 | API REST + Challenges | En cours |
| 2 | GraphQL | Planifié |
| 3 | Mode Documentation | Planifié |
| 4 | Frontend | Planifié |

## Documentation

Voir [PROJECT_SPEC.md](PROJECT_SPEC.md) pour la spécification complète.

## Licence

[À définir]
