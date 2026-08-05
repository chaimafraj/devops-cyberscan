from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [('scanner', '0006_scan_async_status')]

    operations = [
        migrations.AddConstraint(
            model_name='notification',
            constraint=models.UniqueConstraint(
                fields=('scan', 'type', 'titre'),
                name='unique_notification_per_scan_type_title',
            ),
        ),
        migrations.CreateModel(
            name='RealtimeEvent',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('event_type', models.CharField(db_index=True, max_length=50)),
                ('payload', models.JSONField(blank=True, default=dict)),
                ('created_at', models.DateTimeField(auto_now_add=True, db_index=True)),
                ('scan', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='realtime_events', to='scanner.scan')),
            ],
            options={'ordering': ['id']},
        ),
        migrations.AddIndex(
            model_name='realtimeevent',
            index=models.Index(fields=['scan', 'id'], name='realtime_scan_id_idx'),
        ),
    ]