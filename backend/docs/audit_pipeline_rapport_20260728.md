# Audit du pipeline de rapport CyberScan — 28 juillet 2026

## Périmètre contrôlé

Pipeline vérifié de bout en bout :

1. Sorties SSLScan, OpenSSL, Nmap, WhatWeb, ZAP, Nuclei, SSL Labs et NVD.
2. Résultat retourné par `scan_single_site`.
3. Persistance synchrone et persistance Celery dans `Scan.resultats_ssl` et `CVE`.
4. Normalisation des données techniques et des CVE.
5. Score IA, niveau de risque, priorité et contexte IA.
6. Compteurs, alertes, notifications, chatbot, exports JSON/Excel.
7. Génération et validation du PDF.

## Bugs corrigés

1. Le modèle `CVE` ne conservait ni le produit concerné ni le lien NVD.
2. Les chemins synchrone et Celery dupliquaient la construction de `resultats_ssl`.
3. Les deux chemins de persistance perdaient les métadonnées CVE après le scanner.
4. La fusion CVE privilégiait parfois une ligne incomplète de la base et ignorait les champs NVD existants.
5. Des identifiants de templates Nuclei pouvaient être enregistrés et comptés comme des CVE.
6. TLS 1.0 était associé automatiquement à `CVE-2014-3566`, alors que ce signal ne prouve pas POODLE/SSLv3.
7. RC4 pouvait être associé à `CVE-2016-2183`, alors que SWEET32 requiert une preuve Triple-DES.
8. Le motif 3DES ne reconnaissait pas les noms SSLScan contenant des underscores, par exemple `TLS_RSA_WITH_3DES_EDE_CBC_SHA`.
9. Les anciennes associations POODLE sont filtrées lorsqu’SSLScan montre `SSLv3 disabled`.
10. Le produit SWEET32 historique est récupéré uniquement lorsqu’une ligne 3DES est réellement enregistrée.
11. L’annexe PDF CVE ne contenait que l’identifiant, le CVSS et la description.
12. Le lien NVD n’était pas cliquable dans le PDF.
13. Les compteurs du tableau de bord, les alertes, les notifications, le chatbot et les exports pouvaient diverger du PDF.
14. La liste des outils des exports était codée en dur.
15. Deux implémentations NVD existaient.
16. Deux anciens générateurs PDF dupliqués et non utilisés existaient.
17. Les compteurs, graphiques et sections narratives utilisaient auparavant plusieurs sources divergentes.
18. Les champs certificat, TLS, cipher suites, IP, ASN, hébergeur, serveur Web, ports, services, technologies, durée et outils n’étaient pas tous récupérés depuis les résultats réels.
19. Les seuils score/niveau/priorité n’étaient pas centralisés.
20. Les quatre sections narratives pouvaient utiliser des valeurs génériques au lieu des constats réels.

## Règles exactes appliquées aux CVE

- Un identifiant est une CVE uniquement s’il respecte `CVE-AAAA-NNNN...`.
- Le lien NVD est déterminé à partir de cet identifiant valide.
- Le produit est conservé depuis le produit/version réellement corrélé par NVD ou depuis une preuve scanner explicite.
- Une valeur vide ne remplace jamais une valeur déjà présente.
- Les doublons sont fusionnés par CVE ID.
- TLS 1.0 reste une vulnérabilité de configuration, pas une preuve de POODLE.
- SWEET32 n’est associé que lorsqu’une chaîne `3DES` ou `DES-CBC3` est présente dans SSLScan.

## Fichiers et fonctions modifiés

### Collecte et persistance

- `scanner/views.py`
  - `scan_single_site`
  - `scans_list`
- `scanner/tasks.py`
  - `execute_scan`
- `scanner/scan_persistence.py`
  - `build_stored_results`
  - `cve_instances`
  - `replace_scan_cves`
- `scanner/models.py`
  - champs `CVE.produit_concerne`
  - champ `CVE.lien_nvd`
- `scanner/migrations/0009_cve_product_nvd_link.py`
  - `populate_existing_cve_metadata`

### CVE et NVD

- `scanner/cve_data.py`
  - `normalize_cve_id`
  - `nvd_url_for`
  - `normalize_cve_record`
  - `merge_cve_records`
  - `collect_scan_cves`
  - `cve_model_values`
- `scanner/nvd_service.py`
  - `find_cves_for_technologies`
- `scanner/nvd_client.py`
  - remplacé par une façade de compatibilité vers `nvd_service`
- `scanner/serializers.py`
  - `CVESerializer`
  - `ScanSummarySerializer.get_cves_count`

### Traitement, IA et statistiques

- `scanner/report_data.py`
  - `collect_cves`
  - `build_report_metrics`
  - `normalize_results`
  - fonctions d’extraction réseau, TLS, certificats, durée, technologies et outils
- `scanner/risk_policy.py`
  - `normalize_score`
  - `level_from_score`
  - `priority_from_score`
  - `recommendation_order`
- `scanner/report_analysis.py`
  - `build_report_analysis`
- `scanner/ai_module/chatbot.py`
  - `collect_scan_facts`
- `scanner/dashboard_service.py`
  - `build_dashboard_payload`
- `scanner/alert_service.py`
  - `build_alerts`
- `scanner/notification_service.py`
  - `notify_critical_cve`
  - `notify_scan_events`
- `scanner/scan_queries.py`
  - `scan_summary_queryset`

### PDF et exports

- `scanner/report_fixed.py`
  - `_build_findings`
  - `_finding`
  - `_link_cell`
  - `generate_fixed_pdf_for_scan`
  - suppression de `_previous_generate_fixed_pdf_for_scan`
- `scanner/report_generator.py`
  - `risk_level_from_score`
  - `_collect_tools_used`
  - `_build_remediation_plan`
  - `_collect_recommendations`
  - `build_report_context`
  - `generate_pdf_for_scan`
  - suppression de `_legacy_generate_pdf_for_scan`
- `scanner/report_graphics.py`
  - `_ai_box`
  - `graphical_indicators`
- `scanner/report_excel.py`
  - `build_excel_workbook`
- `scanner/ssl_certificate.py`
  - `extract_certificate`
- `backend/settings.py`
  - paramètres de récupération des métadonnées réseau

### Tests

- `scanner/test_cve_pipeline.py`
- `scanner/test_ssl_certificate.py`
- `scanner/test_report_data.py`
- `scanner/test_report_analysis.py`

## Validation

- 24 tests CVE/SSL/données/rapport : réussis.
- 53 tests CVE/SSL/données/rapport/chatbot : réussis.
- `python manage.py check` : aucune erreur.
- `python manage.py makemigrations --check --dry-run` : aucun changement manquant.
- `git diff --check` : aucune erreur de whitespace.
- Migration `scanner.0009_cve_product_nvd_link` : appliquée.
- PDF réel : 12 pages A4.
- Couverture avant/après : dimensions, polices, tailles et couleurs identiques.
- Annexe : cinq champs présents.
- Lien NVD PDF : annotation cliquable vérifiée.
- `CVE-2014-3566` incorrecte : absente du rapport validé.
- Chaîne `Non disponible` : absente du rapport validé.

PDF validé :

`media/rapports/rapport_cyberscan_124_google.com_20260728_130019.pdf`

La suite complète contient 69 tests. Elle conserve sept échecs préexistants hors de ce changement :

- deux imports liés à `InvalidScanTarget`/`validate_scan_target` ;
- quatre incohérences de normalisation des erreurs API, dont une notification ;
- un test de réutilisation du refresh token après logout.

Ces échecs existaient avant l’audit du rapport et ne sont pas provoqués par les modifications CVE/PDF.

## Code complet

Le code complet est disponible dans les fichiers listés ci-dessus et dans l’archive :

`artifacts/pipeline_report_complete_code_20260728.zip`
