"""
Signaux Django liés aux rapports.

Note d'architecture
-------------------
La génération du PDF et l'envoi d'email ne sont PAS branchés sur
post_save(Scan) : à la création du Scan, les CVE ne sont pas encore
persistées (boucle CVE.objects.create après Scan.objects.create dans
views.scans_list). Un signal post_save produirait un rapport incomplet.

Le point d'entrée officiel est :

    from scanner.report_pipeline import finalize_scan_report
    finalize_scan_report(scan, extra_emails=[...])

appelé juste après la création des CVE.
"""
