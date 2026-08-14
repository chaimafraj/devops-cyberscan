from rest_framework import serializers
from .models import Scan, CVE, User, VulnerabiliteManuelle, Notification
from .cve_data import collect_scan_cves
from .report_data import extract_duration_seconds
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer


class ChatbotRequestSerializer(serializers.Serializer):
    question = serializers.CharField(
        required=True, allow_blank=False, trim_whitespace=True, max_length=1000,
    )
    scan_id = serializers.IntegerField(required=False, allow_null=True, min_value=1)
    conversation_id = serializers.IntegerField(required=False, allow_null=True, min_value=1)
    new_conversation = serializers.BooleanField(required=False, default=False)
    regenerate = serializers.BooleanField(required=False, default=False)

    def to_internal_value(self, data):
        """Accepte `message`/`prompt` des anciens clients comme alias de `question`."""
        normalized = data.copy()
        if not normalized.get('question'):
            for alias in ('message', 'prompt'):
                if normalized.get(alias):
                    normalized['question'] = normalized[alias]
                    break
        return super().to_internal_value(normalized)


class ChatbotResponseSerializer(serializers.Serializer):
    answer = serializers.CharField()
    question = serializers.CharField()
    scan_id = serializers.IntegerField(min_value=1)
    conversation_id = serializers.IntegerField(min_value=1)
    context_mode = serializers.ChoiceField(choices=('scan', 'latest_scan'))
    is_report = serializers.BooleanField()
    sections = serializers.DictField(child=serializers.CharField(), required=False)

class CVESerializer(serializers.ModelSerializer):
    class Meta:
        model = CVE
        fields = [
            'id', 'cve_id', 'description', 'cvss_score', 'produit_concerne',
            'lien_nvd', 'recommandation_ia',
        ]


class ScanSummarySerializer(serializers.ModelSerializer):
    client_nom = serializers.SerializerMethodField()
    cves_count = serializers.SerializerMethodField()
    protocols = serializers.SerializerMethodField()
    rapport_status = serializers.SerializerMethodField()
    email_status = serializers.SerializerMethodField()
    manual_vulnerabilities_count = serializers.IntegerField(read_only=True, default=0)
    has_rapport = serializers.BooleanField(source='has_rapport_value', read_only=True, default=False)
    pdf_disponible = serializers.BooleanField(source='has_rapport_value', read_only=True, default=False)

    class Meta:
        model = Scan
        fields = [
            'id', 'domaine', 'date_scan', 'score_risque_ia', 'status',
            'error_message', 'client_nom', 'protocols', 'cves_count',
            'manual_vulnerabilities_count', 'has_rapport', 'pdf_disponible',
            'rapport_status', 'email_status',
        ]

    def get_client_nom(self, obj):
        return obj.client.nom if obj.client else '—'

    def get_cves_count(self, obj):
        results = obj.resultats_ssl if isinstance(obj.resultats_ssl, dict) else {}
        return len(collect_scan_cves(obj, results))

    def get_protocols(self, obj):
        results = obj.resultats_ssl if isinstance(obj.resultats_ssl, dict) else {}
        protocols = results.get('protocols')
        return protocols if isinstance(protocols, list) else []

    def get_rapport_status(self, obj):
        has_rapport = getattr(obj, 'has_rapport_value', None)
        if has_rapport is None:
            has_rapport = obj.rapports.exists()
        return 'pret' if has_rapport else 'non_genere'

    def get_email_status(self, obj):
        email_sent = getattr(obj, 'email_sent_value', None)
        email_failed = getattr(obj, 'email_failed_value', None)
        if email_sent is not None or email_failed is not None:
            if email_sent:
                return 'envoye'
            if email_failed:
                return 'erreur'
            return 'non_envoye'

        notifications = obj.notifications
        if notifications.filter(type='report_emailed').exists():
            return 'envoye'
        if notifications.filter(type='email_failed').exists():
            return 'erreur'
        return 'non_envoye'

class ScanSerializer(serializers.ModelSerializer):
    cves = CVESerializer(many=True, read_only=True)
    client_nom = serializers.SerializerMethodField()
    pdf_disponible = serializers.SerializerMethodField()
    has_rapport = serializers.SerializerMethodField()

    class Meta:
        model = Scan
        fields = [
            'id', 'domaine', 'date_scan', 'resultats_ssl', 'score_risque_ia',
            'status', 'error_message', 'started_at', 'completed_at',
            'cves', 'client_nom', 'pdf_disponible', 'has_rapport',
        ]

    def get_client_nom(self, obj):
        return obj.client.nom if obj.client else '—'

    def get_pdf_disponible(self, obj):
        return obj.rapports.exists()

    def get_has_rapport(self, obj):
        return obj.rapports.exists()


class ScanDetailSerializer(ScanSerializer):
    duration_seconds = serializers.SerializerMethodField()
    email_status = serializers.SerializerMethodField()
    report_status = serializers.SerializerMethodField()
    timeline = serializers.SerializerMethodField()

    class Meta(ScanSerializer.Meta):
        fields = ScanSerializer.Meta.fields + [
            'duration_seconds', 'email_status', 'report_status', 'timeline',
        ]

    def get_duration_seconds(self, obj):
        results = obj.resultats_ssl if isinstance(obj.resultats_ssl, dict) else {}
        return extract_duration_seconds(obj, results)

    def get_email_status(self, obj):
        notifications = obj.notifications
        if notifications.filter(type='report_emailed').exists():
            return 'envoye'
        if notifications.filter(type='email_failed').exists():
            return 'erreur'
        return 'non_envoye'

    def get_report_status(self, obj):
        return 'pret' if obj.rapports.exists() else 'non_genere'

    def get_timeline(self, obj):
        labels = {
            'scan.queued': 'Scan mis en file',
            'scan.running': 'Scan lance',
            'scan.completed': 'Scan termine',
            'scan.failed': 'Echec du scan',
            'scan.cancelled': 'Scan annule',
            'report.created': 'Rapport genere',
        }
        items = []
        for event in obj.realtime_events.order_by('created_at'):
            label = labels.get(event.event_type)
            if label:
                items.append({
                    'type': event.event_type,
                    'label': label,
                    'timestamp': event.created_at,
                    'payload': event.payload,
                })
        return items


class NotificationSerializer(serializers.ModelSerializer):
    title = serializers.CharField(source='titre', read_only=True)
    description = serializers.CharField(source='message', read_only=True)
    timestamp = serializers.DateTimeField(source='date_creation', read_only=True)
    read = serializers.BooleanField(source='lu', read_only=True)
    type = serializers.SerializerMethodField()

    class Meta:
        model = Notification
        fields = ['id', 'type', 'title', 'description', 'timestamp', 'read']
        read_only_fields = fields

    def get_type(self, obj):
        if obj.niveau == 'critical':
            return 'alert'
        if obj.niveau == 'warning':
            return 'warning'
        if obj.niveau == 'success' or obj.type in {
            'scan_finished', 'report_ready', 'report_emailed',
        }:
            return 'success'
        return 'info'

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'role', 'is_active']


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'role']

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data.get('email', ''),
            password=validated_data['password'],
            role=validated_data.get('role', 'viewer'),
        )
        return user


class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['role'] = user.role
        token['username'] = user.username
        return token

    def validate(self, attrs):
        data = super().validate(attrs)

        must_change = False
        if hasattr(self.user, 'client_profile'):
            must_change = self.user.client_profile.must_change_password

        data['user'] = {
            'id': self.user.id,
            'username': self.user.username,
            'email': self.user.email,
            'role': self.user.role,
            'must_change_password': must_change,
        }
        return data


class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['role'] = user.role
        token['username'] = user.username
        return token

    def validate(self, attrs):
        data = super().validate(attrs)

        must_change = False
        if hasattr(self.user, 'client_profile'):
            must_change = self.user.client_profile.must_change_password

        data['user'] = {
            'id': self.user.id,
            'username': self.user.username,
            'email': self.user.email,
            'role': self.user.role,
            'must_change_password': must_change,
        }
        return data


class VulnerabiliteManuelleSerializer(serializers.ModelSerializer):
    ajoutee_par_username = serializers.SerializerMethodField()

    class Meta:
        model = VulnerabiliteManuelle
        fields = [
            'id', 'scan', 'type_vuln', 'nom', 'impacted_element', 'description',
            'risk', 'cvss_score', 'cvss_vector', 'priorite', 'complexite',
            'technical_business_risks', 'recommandation', 'proof_of_concept',
            'references', 'date_ajout', 'ajoutee_par_username',
        ]
        read_only_fields = ['date_ajout']

    def get_ajoutee_par_username(self, obj):
        return obj.ajoutee_par.username if obj.ajoutee_par else '—'
