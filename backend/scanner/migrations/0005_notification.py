# Generated manually for Notification model

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0004_vulnerabilitemanuelle'),
    ]

    operations = [
        migrations.CreateModel(
            name='Notification',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('titre', models.CharField(max_length=255)),
                ('message', models.TextField()),
                ('type', models.CharField(
                    choices=[
                        ('scan_finished', 'Scan terminé'),
                        ('new_cve', 'Nouvelle CVE'),
                        ('high_risk', 'Risque élevé'),
                        ('report_ready', 'Rapport disponible'),
                    ],
                    max_length=30,
                )),
                ('niveau', models.CharField(
                    choices=[
                        ('info', 'Info'),
                        ('warning', 'Avertissement'),
                        ('critical', 'Critique'),
                    ],
                    default='info',
                    max_length=20,
                )),
                ('lu', models.BooleanField(default=False)),
                ('date_creation', models.DateTimeField(auto_now_add=True)),
                ('scan', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='notifications',
                    to='scanner.scan',
                )),
            ],
            options={
                'ordering': ['-date_creation'],
            },
        ),
    ]
