from django.db import migrations, models


def populate_existing_cve_metadata(apps, schema_editor):
    CVE = apps.get_model("scanner", "CVE")
    for cve in CVE.objects.select_related("scan").iterator():
        cve_id = str(cve.cve_id or "").upper()
        if not cve_id.startswith("CVE-"):
            continue
        updates = {
            "lien_nvd": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        }
        results = cve.scan.resultats_ssl if isinstance(cve.scan.resultats_ssl, dict) else {}
        source = next(
            (
                item
                for item in results.get("nvd_cves") or []
                if isinstance(item, dict) and str(item.get("cve_id") or "").upper() == cve_id
            ),
            {},
        )
        product = source.get("produit_concerne")
        if not product:
            products = source.get("products") or source.get("technologies") or []
            if not isinstance(products, list):
                products = [products]
            product = ", ".join(str(item).strip() for item in products if str(item).strip())
        if product:
            updates["produit_concerne"] = str(product)[:500]
        CVE.objects.filter(pk=cve.pk).update(**updates)


class Migration(migrations.Migration):
    dependencies = [
        ("scanner", "0008_chat_conversation_history"),
    ]

    operations = [
        migrations.AddField(
            model_name="cve",
            name="lien_nvd",
            field=models.URLField(blank=True, max_length=500),
        ),
        migrations.AddField(
            model_name="cve",
            name="produit_concerne",
            field=models.CharField(blank=True, max_length=500),
        ),
        migrations.RunPython(populate_existing_cve_metadata, migrations.RunPython.noop),
    ]