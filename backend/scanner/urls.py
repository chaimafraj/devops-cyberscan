from django.urls import path
from . import vuln_manuelle_views
from . import views
from . import auth_views
from . import client_views
from . import alertes_views
from . import report_views
from . import notification_views
from . import scan_submission
from . import chatbot_views
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from scanner.serializers import MyTokenObtainPairSerializer


class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer


urlpatterns = [
# --- Vulnérabilités Manuelles ---
    path('api/vuln-templates/', vuln_manuelle_views.vuln_templates, name='vuln_templates'),
    path('api/scans/<int:scan_id>/vulnerabilites/', vuln_manuelle_views.vuln_manuelle_list, name='vuln_manuelle_list'),
    path('api/vulnerabilites/<int:pk>/', vuln_manuelle_views.vuln_manuelle_detail, name='vuln_manuelle_detail'),

    # --- Auth Endpoints ---
    path('api/auth/register/', views.register_user, name='auth_register'),
    path('api/auth/login/', MyTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/auth/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/auth/change-password/', auth_views.change_password_view, name='change_password'),
    path('api/auth/logout/', auth_views.logout_view, name='logout'),

    # --- Scanner Endpoints ---
    path('api/test/', views.test_api),
    path('api/scans/', views.scans_list),
    path('api/scans/<int:pk>/', views.scan_detail),
    path('api/scans/<int:pk>/cancel/', scan_submission.cancel_scan, name='scan_cancel'),
    # --- Rapports PDF (consultation + téléchargement + email) ---
    path('api/scans/<int:pk>/rapport/', report_views.scan_rapport_detail, name='scan_rapport_detail'),
    path('api/scans/<int:pk>/rapport/download/', report_views.scan_rapport_download, name='scan_rapport_download'),
    path('api/scans/<int:pk>/rapport/regenerate/', report_views.scan_rapport_regenerate, name='scan_rapport_regenerate'),
    path('api/scans/<int:pk>/rapport/email/', report_views.scan_rapport_email, name='scan_rapport_email'),
    path('api/scans/<int:pk>/rapport/email-download/', report_views.scan_report_email_download, name='scan_report_email_download'),
    path('api/scans/<int:pk>/rapport/qr/', report_views.scan_report_qr, name='scan_report_qr'),
    path('api/scans/<int:pk>/export/json/', report_views.scan_export_json, name='scan_export_json'),
    path('api/scans/<int:pk>/export/excel/', report_views.scan_export_excel, name='scan_export_excel'),
    path('api/dashboard-stats/', views.dashboard_stats, name='dashboard_stats'),

    # --- Notifications ---
    path('api/notifications/', notification_views.notifications_list, name='notifications_list'),
    path('api/notifications/unread-count/', notification_views.notifications_unread_count, name='notifications_unread_count'),
    path('api/notifications/read-all/', notification_views.notifications_mark_all_read, name='notifications_mark_all_read'),
    path('api/notifications/<int:pk>/read/', notification_views.notification_mark_read, name='notification_mark_read'),
    path('api/notifications/<int:pk>/', notification_views.notification_delete, name='notification_delete'),

    # --- Alertes Endpoint ---
    path('api/alertes/', alertes_views.alertes_list, name='alertes_list'),

    # --- Chatbot RAG (Flan-T5) ---
    path('api/chatbot/', chatbot_views.chatbot_ask, name='chatbot_ask'),

    # --- Clients Endpoints (Admin) ---
    path('api/clients/', client_views.clients_list, name='clients_list'),
    path('api/clients/<int:pk>/', client_views.client_detail, name='client_detail'),

    # --- Sites Endpoints (Client) ---
    path('api/sites/', client_views.my_sites, name='my_sites'),
    path('api/sites/<int:pk>/', client_views.site_detail, name='site_detail'),
]
