# API Chatbot CyberScan

## Endpoint

`POST /api/chatbot/`

Authentification JWT requise. Une requête valide renvoie toujours `HTTP 200 OK`, quelle que soit la longueur de `answer` et quelle que soit la valeur de `is_report`.

## Corps de la requête

```json
{
  "question": "Quels sont les risques ?",
  "scan_id": 42,
  "conversation_id": 7,
  "new_conversation": false,
  "regenerate": false
}
```

| Champ | Type | Obligatoire | Description |
|---|---|---:|---|
| `question` | string | oui | Question courante, non vide, 1 000 caractères maximum. Pour compatibilité, `message` et `prompt` sont acceptés comme alias, mais `question` reste le nom officiel. |
| `scan_id` | integer | non | Scan à analyser. Sans valeur, le dernier scan accessible est utilisé. |
| `conversation_id` | integer | non | Conversation à poursuivre. Le frontend doit réutiliser l’identifiant renvoyé par l’API. |
| `new_conversation` | boolean | non | Crée une nouvelle conversation. Valeur par défaut : `false`. |
| `regenerate` | boolean | non | Redemande explicitement le rapport structuré dans le chat. Valeur par défaut : `false`. Ce flag ne régénère pas le fichier PDF. |

## Réponse de succès

Champs stables — aucun n’a été renommé :

| Champ | Type | Présence | Description |
|---|---|---|---|
| `answer` | string | toujours | Texte à afficher. Rapport structuré au premier tour ou avec `regenerate: true`; sinon réponse conversationnelle ciblée. |
| `context_mode` | string | toujours | `scan` si `scan_id` a été fourni, sinon `latest_scan`. |
| `conversation_id` | integer | toujours | Identifiant à renvoyer lors des questions suivantes. |
| `is_report` | boolean | toujours | `true` uniquement pour une demande explicite de rapport complet ou avec `regenerate: true`. |
| `question` | string | toujours | Question normalisée reçue par le backend. |
| `scan_id` | integer | toujours | Identifiant du scan effectivement utilisé. |
| `sections` | object de strings | conditionnel | Présent uniquement quand `is_report` vaut `true`; absent quand `is_report` vaut `false`. |

### Demande explicite de rapport ou régénération

Statut : `200 OK`.

```json
{
  "answer": "Résumé\n...",
  "context_mode": "scan",
  "conversation_id": 7,
  "is_report": true,
  "question": "Présente le scan",
  "scan_id": 42,
  "sections": {
    "Résumé": "...",
    "Risque": "...",
    "Score": "8.6/10",
    "Vulnérabilités": "...",
    "Impact": "...",
    "Recommandations": "...",
    "Commandes utiles": "...",
    "Conclusion IA": "..."
  }
}
```

### Question de suivi

Statut : `200 OK`. `sections` est volontairement absent.

```json
{
  "answer": "Le risque principal est ...",
  "context_mode": "scan",
  "conversation_id": 7,
  "is_report": false,
  "question": "Quels sont les risques ?",
  "scan_id": 42
}
```

## Actions rapport distinctes

- Voir le rapport PDF : `GET /api/scans/<scan_id>/rapport/`
- Régénérer le rapport PDF : `POST /api/scans/<scan_id>/rapport/regenerate/`
- Régénérer seulement la réponse structurée dans le chat : `POST /api/chatbot/` avec `regenerate: true`

## Erreurs principales

- `400 Bad Request` : corps invalide ou question absente.
- `401 Unauthorized` : authentification absente ou invalide.
- `403 Forbidden` : scan non accessible.
- `404 Not Found` : scan ou conversation introuvable/incompatible.
- `429 Too Many Requests` : limite du chatbot dépassée.
- `500 Internal Server Error` : réponse interne impossible à sérialiser.