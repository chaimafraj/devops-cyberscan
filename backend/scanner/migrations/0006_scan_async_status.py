from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('scanner', '0005_notification')]

    operations = [
        migrations.AddField(model_name='scan', name='status', field=models.CharField(choices=[('PENDING', 'En attente'), ('RUNNING', 'En cours'), ('COMPLETED', 'Termine'), ('FAILED', 'Echoue')], db_index=True, default='PENDING', max_length=10)),
        migrations.AddField(model_name='scan', name='error_message', field=models.TextField(blank=True)),
        migrations.AddField(model_name='scan', name='celery_task_id', field=models.CharField(blank=True, db_index=True, max_length=255)),
        migrations.AddField(model_name='scan', name='started_at', field=models.DateTimeField(blank=True, null=True)),
        migrations.AddField(model_name='scan', name='completed_at', field=models.DateTimeField(blank=True, null=True)),
    ]
