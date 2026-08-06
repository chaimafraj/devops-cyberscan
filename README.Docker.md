# CyberScan avec Docker Compose

Cette configuration lance l'application complète : Angular, Django/Gunicorn,
Celery, PostgreSQL et Redis.

## Démarrage

1. Créez votre fichier de configuration :

   ```powershell
   Copy-Item .env.example .env
   ```

2. Remplacez au minimum `DJANGO_SECRET_KEY`, `POSTGRES_PASSWORD` et
   `INITIAL_ADMIN_PASSWORD` dans `.env`. Vous pouvez aussi personnaliser
   `INITIAL_ADMIN_USERNAME` et `INITIAL_ADMIN_EMAIL`.

3. Construisez et démarrez les services :

   ```powershell
   docker compose up --build -d
   ```

4. Ouvrez `http://localhost:4200`. L'API reste également accessible sur
   `http://localhost:8000`. Connectez-vous avec les identifiants
   `INITIAL_ADMIN_USERNAME` et `INITIAL_ADMIN_PASSWORD` de votre fichier `.env`.

Le compte initial est créé automatiquement après les migrations. La commande
est idempotente : les redéploiements conservent un mot de passe modifié depuis
l'application.

## Commandes utiles

```powershell
docker compose ps
docker compose logs -f backend worker
docker compose exec backend python manage.py createsuperuser
docker compose down
```

Les rapports de `backend/media` restent sur l'hôte. Les données PostgreSQL,
Redis, les fichiers statiques Django et le cache Hugging Face utilisent des
volumes Docker persistants.

`POSTGRES_PASSWORD` n'est appliqué par l'image PostgreSQL que lors de la
création initiale du volume `postgres_data`. Le modifier ensuite dans `.env`
ne change pas le mot de passe du rôle déjà stocké dans la base. Pour une
installation existante, faites d'abord une rotation du mot de passe dans
PostgreSQL, ou recréez volontairement le volume si ses données sont jetables.

`docker compose down -v` supprime aussi les volumes et donc les données de la
base. Ne l'utilisez que si cette suppression est voulue.

Les commandes `sslscan`, `nmap`, `openssl` et `whatweb` sont exécutées
directement dans le conteneur `worker`; aucune connexion SSH n'est utilisée.

ZAP est lancé par le Docker du serveur. Avant le démarrage, renseignez
`DOCKER_GID` dans `.env` avec le groupe du socket Docker :

```bash
stat -c '%g' /var/run/docker.sock
```

Le socket `/var/run/docker.sock` donne au worker un contrôle important sur le
serveur Docker. Ne donnez l'accès à l'application et à son code qu'à des
utilisateurs de confiance.
