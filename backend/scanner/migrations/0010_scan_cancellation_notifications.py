from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('scanner', '0009_cve_product_nvd_link')]

    operations = [
        migrations.AlterField(
            model_name='scan',
            name='status',
            field=models.CharField(
                choices=[
                    ('PENDING', 'En attente'),
                    ('RUNNING', 'En cours'),
                    ('COMPLETED', 'Termine'),
                    ('FAILED', 'Echoue'),
                    ('CANCELLED', 'Annule'),
                ],
                db_index=True,
                default='PENDING',
                max_length=10,
            ),
        ),
        migrations.AlterField(
            model_name='notification',
            name='type',
            field=models.CharField(
                choices=[
                    ('scan_started', 'Scan démarré'),
                    ('scan_finished', 'Scan terminé'),
                    ('scan_cancelled', 'Scan annulé'),
                    ('scan_failed', 'Échec du scan'),
                    ('new_cve', 'Nouvelle CVE'),
                    ('high_risk', 'Risque élevé'),
                    ('report_ready', 'Rapport disponible'),
                    ('report_failed', 'Échec du rapport'),
                    ('report_emailed', 'Rapport envoyé'),
                    ('email_failed', 'Échec de l’envoi'),
                ],
                max_length=30,
            ),
        ),
        migrations.AlterField(
            model_name='notification',
            name='niveau',
            field=models.CharField(
                choices=[
                    ('info', 'Info'),
                    ('success', 'Succès'),
                    ('warning', 'Avertissement'),
                    ('critical', 'Critique'),
                ],
                default='info',
                max_length=20,
            ),
        ),
    ]
