# Synchronisation temps réel CyberScan (SSE)

Endpoint authentifié : `GET /api/realtime/events/`

Le client doit ouvrir le flux avec `fetch` afin d’envoyer le JWT :

```ts
const response = await fetch('/api/realtime/events/', {
  headers: { Authorization: `Bearer ${accessToken}` },
});
const reader = response.body!.getReader();
```

Le type MIME est `text/event-stream`. Le premier événement `snapshot` contient le
nombre réel de notifications non lues et les ressources à charger. Les événements
suivants portent notamment les types :

- `scan.queued`, `scan.running`, `scan.completed`, `scan.failed` ;
- `notification.created`, `notification.updated`, `notification.deleted` ;
- `vulnerability.created`, `vulnerability.deleted` ;
- `report.created`.

Chaque événement contient `resources`. Le frontend doit relancer uniquement les GET
correspondants (`dashboard`, `scans`, `alerts`, `notifications`, `reports` ou
`chatbot`). Le champ `unread_count` peut mettre à jour directement le badge.

Pour une reconnexion, renvoyer le dernier identifiant reçu dans l’en-tête
`Last-Event-ID`. Sans identifiant, le serveur envoie un snapshot actuel et ne rejoue
pas l’historique ancien.

Les réponses API dynamiques utilisent `Cache-Control: no-store`.