# CyberScan avec Docker Compose

Cette configuration lance l'application complète : Angular, Django/Gunicorn,
Celery, PostgreSQL et Redis.

## Démarrage

1. Créez votre fichier de configuration :

   ```powershell
   Copy-Item .env.example .env
   ```

2. Remplacez au minimum `DJANGO_SECRET_KEY` et `POSTGRES_PASSWORD` dans `.env`.

3. Construisez et démarrez les services :

   ```powershell
   docker compose up --build -d
   ```

4. Ouvrez `http://localhost:4200`. L'API reste également accessible sur
   `http://localhost:8000`.

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

`docker compose down -v` supprime aussi les volumes et donc les données de la
base. Ne l'utilisez que si cette suppression est voulue.

Le backend contacte une machine de scan par SSH. Renseignez `SSH_HOST`,
`SSH_USER` et `SSH_PASSWORD` dans `.env` si les scans distants sont nécessaires.
