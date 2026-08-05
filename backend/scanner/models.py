from django.db import models
from django.contrib.auth.models import AbstractUser
import secrets
import string


class User(AbstractUser):
    ROLE_CHOICES = [
        ('admin', 'Administrateur'),
        ('analyst', 'Analyste Sécurité'),
        ('viewer', 'Lecteur'),
        ('client', 'Client'),
    ]
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='viewer')
    email = models.EmailField(unique=True)

    def __str__(self):
        return f"{self.username} ({self.role})"


class Scan(models.Model):
    class Status(models.TextChoices):
        PENDING = 'PENDING', 'En attente'
        RUNNING = 'RUNNING', 'En cours'
        COMPLETED = 'COMPLETED', 'Termine'
        FAILED = 'FAILED', 'Echoue'
        CANCELLED = 'CANCELLED', 'Annule'

    domaine = models.CharField(max_length=255)
    date_scan = models.DateTimeField(auto_now_add=True)
    resultats_ssl = models.JSONField(default=dict)
    score_risque_ia = models.FloatField(default=0.0)
    status = models.CharField(
        max_length=10,
        choices=Status.choices,
        default=Status.PENDING,
        db_index=True,
    )
    error_message = models.TextField(blank=True)
    celery_task_id = models.CharField(max_length=255, blank=True, db_index=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name='scans'
    )
    client = models.ForeignKey(
        'Client', on_delete=models.CASCADE, null=True, blank=True, related_name='scans_client'
    )

    def __str__(self):
        return f"{self.domaine} - {self.date_scan}"


class RealtimeEvent(models.Model):
    event_type = models.CharField(max_length=50, db_index=True)
    payload = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    scan = models.ForeignKey(
        Scan,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='realtime_events',
    )

    class Meta:
        ordering = ['id']
        indexes = [
            models.Index(fields=['scan', 'id'], name='realtime_scan_id_idx'),
        ]

    def __str__(self):
        return f'{self.event_type} ({self.id})'


class CVE(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='cves')
    cve_id = models.CharField(max_length=50)
    description = models.TextField()
    cvss_score = models.FloatField(default=0.0)
    recommandation_ia = models.TextField(null=True, blank=True)
    produit_concerne = models.CharField(max_length=500, blank=True)
    lien_nvd = models.URLField(max_length=500, blank=True)

    def __str__(self):
        return self.cve_id


class Alerte(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='alertes')
    message = models.TextField()
    date_envoi = models.DateTimeField(auto_now_add=True)


class Rapport(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='rapports')
    chemin_pdf = models.CharField(max_length=500)
    date_generation = models.DateTimeField(auto_now_add=True)


class Notification(models.Model):
    TYPE_CHOICES = [
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
    ]
    NIVEAU_CHOICES = [
        ('info', 'Info'),
        ('success', 'Succès'),
        ('warning', 'Avertissement'),
        ('critical', 'Critique'),
    ]

    titre = models.CharField(max_length=255)
    message = models.TextField()
    type = models.CharField(max_length=30, choices=TYPE_CHOICES)
    niveau = models.CharField(max_length=20, choices=NIVEAU_CHOICES, default='info')
    lu = models.BooleanField(default=False)
    date_creation = models.DateTimeField(auto_now_add=True)
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='notifications')

    class Meta:
        ordering = ['-date_creation']
        constraints = [
            models.UniqueConstraint(
                fields=['scan', 'type', 'titre'],
                name='unique_notification_per_scan_type_title',
            ),
        ]

    def __str__(self):
        return f'{self.titre} ({self.type})'

def generate_temp_password(length=10):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


class Client(models.Model):
    nom = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    user = models.OneToOneField(
        User, on_delete=models.CASCADE, related_name='client_profile',
        null=True, blank=True
    )
    must_change_password = models.BooleanField(default=True)
    date_creation = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='clients_created'
    )
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return self.nom


class Site(models.Model):
    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name='sites')
    domaine = models.CharField(max_length=255)
    date_ajout = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.domaine} ({self.client.nom})"

class VulnerabiliteManuelle(models.Model):
    TYPE_CHOICES = [
        ('idor', 'IDOR - Insecure Direct Object Reference'),
        ('lfi', 'LFI - Local File Inclusion'),
        ('xss', 'XSS - Cross-Site Scripting'),
        ('sqli', 'SQL Injection'),
        ('csrf', 'CSRF'),
        ('broken_auth', 'Broken Authentication'),
        ('sensitive_data', 'Sensitive Data Exposure'),
        ('spam', 'Spam / Abus'),
        ('autre', 'Autre'),
    ]

    RISK_CHOICES = [
        ('critical', 'Critique'),
        ('high', 'Élevé'),
        ('medium', 'Moyen'),
        ('low', 'Faible'),
    ]

    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='vulnerabilites_manuelles')
    type_vuln = models.CharField(max_length=30, choices=TYPE_CHOICES, default='autre')
    nom = models.CharField(max_length=255)
    impacted_element = models.CharField(max_length=500, blank=True)
    description = models.TextField(blank=True)
    risk = models.CharField(max_length=20, choices=RISK_CHOICES, default='medium')
    cvss_score = models.FloatField(default=0.0)
    cvss_vector = models.CharField(max_length=100, blank=True)
    priorite = models.CharField(max_length=50, blank=True)
    complexite = models.CharField(max_length=50, blank=True)
    technical_business_risks = models.TextField(blank=True)
    recommandation = models.TextField(blank=True)
    proof_of_concept = models.TextField(blank=True)
    references = models.TextField(blank=True)
    date_ajout = models.DateTimeField(auto_now_add=True)
    ajoutee_par = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return f"{self.nom} ({self.scan.domaine})"

class ChatConversation(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='chat_conversations')
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='chat_conversations')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True, db_index=True)

    class Meta:
        ordering = ['-updated_at']


class ChatMessage(models.Model):
    class Role(models.TextChoices):
        USER = 'user', 'Utilisateur'
        ASSISTANT = 'assistant', 'Assistant'

    conversation = models.ForeignKey(
        ChatConversation, on_delete=models.CASCADE, related_name='messages'
    )
    role = models.CharField(max_length=10, choices=Role.choices)
    content = models.TextField()
    is_report = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['id']
