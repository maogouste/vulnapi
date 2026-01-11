# Installation de VulnAPI

## Prérequis

### Python
- Python 3.10 ou supérieur
- pip

### Dépendances système (pour les vulnérabilités d'injection)
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y iputils-ping dnsutils

# Arch Linux
sudo pacman -S iputils bind-tools

# RHEL/CentOS
sudo dnf install -y iputils bind-utils
```

## Installation

### 1. Cloner le projet
```bash
git clone <repo-url>
cd vulnapi
```

### 2. Créer l'environnement virtuel
```bash
cd implementations/python-fastapi

# Créer le venv
python3 -m venv venv

# Activer le venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate     # Windows
```

### 3. Installer les dépendances
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Configuration (optionnel)
```bash
# Copier le fichier d'exemple
cp .env.example .env

# Éditer si nécessaire
nano .env
```

### 5. Lancer l'application
```bash
# Mode développement avec rechargement auto
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Mode production
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

### 6. Accéder à l'API
- Documentation Swagger : http://localhost:8000/docs
- Documentation ReDoc : http://localhost:8000/redoc
- API Root : http://localhost:8000/

## Installation avec Docker

```bash
# Depuis la racine du projet
docker-compose up -d

# Logs
docker-compose logs -f vulnapi-python
```

## Vérification de l'installation

```bash
# Tester que l'API répond
curl http://localhost:8000/health

# Réponse attendue :
# {"status":"healthy","debug":true}
```

## Résolution de problèmes

### Erreur "Module not found"
```bash
# S'assurer que le venv est activé
source venv/bin/activate

# Réinstaller les dépendances
pip install -r requirements.txt
```

### Erreur avec ping/nslookup (V07)
Les vulnérabilités d'injection de commandes nécessitent ces outils :
```bash
which ping    # Doit retourner un chemin
which nslookup
```

### Port déjà utilisé
```bash
# Changer le port
uvicorn app.main:app --port 8001
```

### Base de données corrompue
```bash
# Supprimer et relancer (sera recréée automatiquement)
rm vulnapi.db
uvicorn app.main:app --reload
```

## Notes de sécurité

**AVERTISSEMENT** : Cette application contient des vulnérabilités intentionnelles.

- Ne JAMAIS exposer sur Internet sans protection
- Utiliser uniquement dans un environnement isolé
- Idéal : VM dédiée ou conteneur Docker
