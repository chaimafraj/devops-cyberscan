# API de notifications CyberScan

Toutes les routes exigent un JWT valide dans l’en-tête `Authorization: Bearer <access_token>`. Une notification n’est visible et modifiable que par le client auquel appartient son scan. Les administrateurs ont accès à toutes les notifications.

## Lister les notifications

`GET /api/notifications`

Réponse `200 OK` :

```json
{
  "notifications": [{
    "id": 42,
    "type": "success",
    "title": "Scan terminé — example.com",
    "description": "Le scan de sécurité sur example.com est terminé.",
    "timestamp": "2026-07-24T10:15:30Z",
    "read": false
  }],
  "unread_count": 1
}
```

La liste est triée de la plus récente à la plus ancienne et limitée aux 100 premières notifications. `?unread=true` filtre la liste sans changer la signification de `unread_count`. Les types possibles sont `alert`, `success`, `info` et `warning`.

## Compteur seul

`GET /api/notifications/unread-count` retourne `200 OK` avec `{"unread_count": 7}`.

## Tout marquer comme lu

`PATCH /api/notifications/read-all` retourne `200 OK` avec `{"success": true, "updated_count": 7}`. L’opération est idempotente.

## Marquer une notification comme lue

`PATCH /api/notifications/{id}/read` retourne `200 OK` avec `{"success": true, "notification": {…}}`. L’opération est idempotente.

## Statuts et erreurs

- `200 OK` : requête traitée avec succès.
- `401 Unauthorized` : JWT absent, invalide ou expiré.
- `403 Forbidden` : la notification existe mais n’appartient pas à l’utilisateur connecté.
- `404 Not Found` : l’identifiant n’existe pas.
- `405 Method Not Allowed` : méthode HTTP incorrecte.
- `500 Internal Server Error` : erreur serveur inattendue.

Les erreurs applicatives utilisent `{"error": "message"}`. Les erreurs d’authentification et de méthode suivent le format standard de Django REST Framework.

## Temps réel

Le projet ne contient actuellement ni Django Channels, ni serveur SSE, ni transport WebSocket configuré. Aucun événement `notification:new` n’est donc émis. Le frontend peut interroger `/api/notifications/unread-count` à faible fréquence jusqu’à l’ajout d’une infrastructure temps réel.