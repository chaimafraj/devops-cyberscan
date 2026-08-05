"""
Smoke tests for CyberScan API routes, PDF download, and report email.
Run with: python scripts/api_smoke_test.py
(Use the cyberapp conda env if transformers is required.)
"""
from __future__ import annotations

import json
import os
import sys
import traceback

# Project root on path
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'backend.settings')

import django

django.setup()

from django.conf import settings
from django.core import mail
from django.test.utils import override_settings
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from scanner.models import User, Scan, CVE
from scanner.report_pipeline import finalize_scan_report
from scanner.report_generator import generate_pdf_for_scan
from scanner.report_email import (
    send_scan_report_email,
    build_email_body,
    resolve_recipient_emails,
)

results = []


def ok(name, cond, detail=''):
    status = 'PASS' if cond else 'FAIL'
    results.append((status, name, str(detail)))
    print(f'[{status}] {name}' + (f' — {detail}' if detail else ''))


def request_test(client, method, path, expect_status=None, data=None, name=None):
    name = name or f'{method} {path}'
    try:
        fn = getattr(client, method.lower())
        kwargs = {}
        if data is not None:
            kwargs['data'] = data
            kwargs['format'] = 'json'
        resp = fn(path, **kwargs)
        body_preview = ''
        try:
            if hasattr(resp, 'data'):
                body_preview = json.dumps(resp.data, default=str)[:220]
            else:
                body_preview = str(resp.content[:180])
        except Exception:
            body_preview = str(getattr(resp, 'content', b'')[:120])
        if expect_status is None:
            ok(name, True, f'status={resp.status_code}')
        else:
            ok(
                name,
                resp.status_code == expect_status,
                f'got {resp.status_code}, expected {expect_status}; {body_preview}',
            )
        return resp
    except Exception as e:
        ok(name, False, f'EXCEPTION: {e}')
        traceback.print_exc()
        return None


def main():
    admin = (
        User.objects.filter(role='admin').first()
        or User.objects.filter(is_superuser=True).first()
    )
    if not admin:
        admin = User.objects.create_user(
            username='testadmin',
            email='testadmin@cyberscan.local',
            password='TestAdmin123!',
            role='admin',
        )
        ok('create admin', True, admin.username)
    else:
        ok('admin user', True, f'{admin.username} / {admin.email}')

    # Ensure password known for login test (dev smoke only)
    admin.set_password('TestAdmin123!')
    if not admin.email:
        admin.email = 'admin@cyberapp.com'
    admin.save()

    token = str(RefreshToken.for_user(admin).access_token)
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
    anon = APIClient()

    print('=== AUTH / PUBLIC ===')
    # DEFAULT_PERMISSION is IsAuthenticated → 401 for anon
    request_test(anon, 'GET', '/api/test/', 401, name='GET /api/test/ (anon → 401)')
    request_test(client, 'GET', '/api/test/', 200, name='GET /api/test/ (auth → 200)')

    request_test(
        anon,
        'POST',
        '/api/auth/login/',
        401,
        data={'username': admin.username, 'password': 'WRONG'},
        name='POST /api/auth/login/ (bad password)',
    )
    login_ok = request_test(
        anon,
        'POST',
        '/api/auth/login/',
        200,
        data={'username': admin.username, 'password': 'TestAdmin123!'},
        name='POST /api/auth/login/ (valid)',
    )
    if login_ok is not None and login_ok.status_code == 200:
        refresh = login_ok.data.get('refresh')
        request_test(
            anon,
            'POST',
            '/api/auth/refresh/',
            200,
            data={'refresh': refresh},
            name='POST /api/auth/refresh/',
        )

    request_test(client, 'POST', '/api/auth/logout/', None, name='POST /api/auth/logout/')

    print('=== DASHBOARD / SCANS ===')
    request_test(client, 'GET', '/api/dashboard-stats/', 200)
    request_test(client, 'GET', '/api/scans/', 200)
    request_test(client, 'GET', '/api/scans/?page=1&page_size=5', 200)

    scan = Scan.objects.order_by('-id').first()
    if not scan:
        scan = Scan.objects.create(
            domaine='test-rapport.example.com',
            resultats_ssl={
                'sslscan': 'TLSv1.2 enabled',
                'openssl': 'ok',
                'nmap': '443/tcp open',
                'protocols': [{'name': 'TLSv1.2', 'status': 'secure'}],
                'vulnerabilities': [],
                'whatweb': {
                    'success': True,
                    'technologies': [{'name': 'nginx', 'version': ['1.24'], 'string': []}],
                },
                'nvd': {'success': True, 'errors': [], 'cves_count': 1},
                'nvd_cves': [
                    {
                        'cve_id': 'CVE-2020-0001',
                        'cvss_score': 7.5,
                        'severity': 'HIGH',
                        'description': 'test',
                    }
                ],
                'zap_findings': [],
                'zap_success': True,
                'ssllabs': {
                    'grade': 'B',
                    'status': 'ready',
                    'host': 'test-rapport.example.com',
                },
            },
            score_risque_ia=6.5,
            created_by=admin,
        )
        CVE.objects.create(
            scan=scan,
            cve_id='CVE-2020-0001',
            description='Test CVE',
            cvss_score=7.5,
            recommandation_ia='Patcher.',
        )
        ok('seed scan', True, f'id={scan.id}')
    else:
        ok('existing scan', True, f'id={scan.id} domaine={scan.domaine}')
        if scan.created_by_id is None:
            scan.created_by = admin
            scan.save(update_fields=['created_by'])

    request_test(client, 'GET', f'/api/scans/{scan.id}/', 200)
    request_test(client, 'GET', '/api/scans/999999/', 404)

    print('=== RAPPORT PDF ===')
    if not scan.rapports.exists():
        try:
            generate_pdf_for_scan(scan)
            ok('generate PDF for scan', True)
        except Exception as e:
            ok('generate PDF for scan', False, str(e))

    rapport_resp = request_test(client, 'GET', f'/api/scans/{scan.id}/rapport/', 200)
    if rapport_resp is not None and rapport_resp.status_code == 200:
        data = rapport_resp.data
        ok('rapport has contenu', 'contenu' in data and 'rapport' in data, list(data.keys()))
        ok(
            'rapport pdf flag',
            data.get('rapport', {}).get('pdf_disponible') is True,
            data.get('rapport'),
        )
        required = [
            'domaine',
            'score_global_securite',
            'niveau_risque',
            'resume_executif',
            'cves',
        ]
        ok(
            'contenu fields',
            all(k in data.get('contenu', {}) for k in required),
            list(data.get('contenu', {}).keys())[:20],
        )

    dl = request_test(
        client,
        'GET',
        f'/api/scans/{scan.id}/rapport/download/',
        200,
        name=f'GET /api/scans/{scan.id}/rapport/download/',
    )
    if dl is not None and dl.status_code == 200:
        ctype = dl.get('Content-Type', '')
        if hasattr(dl, 'streaming_content'):
            content = b''.join(dl.streaming_content)
        else:
            content = dl.content
        ok('PDF Content-Type', 'pdf' in ctype.lower(), f'ctype={ctype}')
        ok(
            'PDF magic header',
            content[:4] == b'%PDF',
            f'first={content[:8]!r} size={len(content)}',
        )
        out = os.path.join(
            settings.BASE_DIR,
            'media',
            'rapports',
            f'_test_download_scan_{scan.id}.pdf',
        )
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, 'wb') as f:
            f.write(content)
        ok('PDF saved locally', os.path.getsize(out) > 1000, out)

    request_test(
        anon,
        'GET',
        f'/api/scans/{scan.id}/rapport/',
        401,
        name='GET rapport unauth → 401',
    )
    request_test(
        anon,
        'GET',
        f'/api/scans/{scan.id}/rapport/download/',
        401,
        name='GET download unauth → 401',
    )

    print('=== RAPPORT EMAIL API ===')
    with override_settings(EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend'):
        mail.outbox = []
        email_api = request_test(
            client,
            'POST',
            f'/api/scans/{scan.id}/rapport/email/',
            200,
            data={},
            name=f'POST /api/scans/{scan.id}/rapport/email/',
        )
        if email_api is not None and email_api.status_code == 200:
            ok(
                'email API success flag',
                email_api.data.get('success') is True,
                email_api.data,
            )
            ok('email API outbox', len(mail.outbox) >= 1, f'count={len(mail.outbox)}')
        request_test(
            anon,
            'POST',
            f'/api/scans/{scan.id}/rapport/email/',
            401,
            data={},
            name='POST rapport/email unauth → 401',
        )

    print('=== ALERTES / CLIENTS / SITES / VULN ===')
    request_test(client, 'GET', '/api/alertes/', 200)
    request_test(client, 'GET', '/api/clients/', 200)
    request_test(client, 'GET', '/api/sites/', None, name='GET /api/sites/')
    request_test(client, 'GET', '/api/vuln-templates/', 200)
    request_test(client, 'GET', f'/api/scans/{scan.id}/vulnerabilites/', 200)

    # change-password shape check (expect 400 without proper body)
    request_test(
        client,
        'POST',
        '/api/auth/change-password/',
        None,
        data={},
        name='POST /api/auth/change-password/ (empty body)',
    )

    print('=== EMAIL (locmem) ===')
    with override_settings(EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend'):
        mail.outbox = []
        recipients = resolve_recipient_emails(
            scan, extra_emails=['test-report@example.com']
        )
        ok('recipients resolved', len(recipients) >= 1, recipients)
        body = build_email_body(scan)
        ok(
            'email body has fields',
            all(
                x in body
                for x in [
                    'Domaine',
                    'Score global',
                    'Niveau de risque',
                    'Résumé',
                ]
            ),
            body[:140].replace('\n', ' '),
        )
        r = send_scan_report_email(scan, extra_emails=['test-report@example.com'])
        ok('send_scan_report_email success', r.get('success') is True, r)
        ok('outbox has email', len(mail.outbox) == 1, f'count={len(mail.outbox)}')
        if mail.outbox:
            msg = mail.outbox[0]
            ok('email subject CyberScan', 'CyberScan' in msg.subject, msg.subject)
            ok(
                'email has PDF attachment',
                len(msg.attachments) > 0,
                f'n={len(msg.attachments)}',
            )
            att_info = []
            for a in msg.attachments:
                if isinstance(a, tuple):
                    att_info.append(
                        (a[0], len(a[1]) if len(a) > 1 else 0, a[2] if len(a) > 2 else '')
                    )
                else:
                    att_info.append(repr(a)[:80])
            ok('attachment details', True, att_info)
            if msg.attachments:
                a0 = msg.attachments[0]
                if isinstance(a0, tuple) and len(a0) > 1:
                    ok('attachment is PDF bytes', a0[1][:4] == b'%PDF', a0[0])

    print('=== PIPELINE finalize_scan_report ===')
    with override_settings(EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend'):
        mail.outbox = []
        outcome = finalize_scan_report(scan, extra_emails=['pipeline@example.com'])
        ok('pipeline pdf_ok', outcome.get('pdf_ok') is True, outcome)
        email_res = outcome.get('email') or {}
        ok('pipeline email', email_res.get('success') is True, email_res)
        errs = outcome.get('errors') or []
        ok('pipeline errors empty', len(errs) == 0, errs)

    print('=== EMAIL error handling ===')
    with override_settings(
        EMAIL_BACKEND='django.core.mail.backends.smtp.EmailBackend',
        EMAIL_HOST='invalid.smtp.localhost',
        EMAIL_PORT=1,
        EMAIL_HOST_USER='x',
        EMAIL_HOST_PASSWORD='y',
    ):
        bad = send_scan_report_email(scan, extra_emails=['fail@example.com'])
        ok(
            'email failure captured (no exception)',
            bad.get('success') is False and bad.get('error'),
            bad,
        )

    print('=== SMTP settings present ===')
    ok(
        'EMAIL settings present',
        bool(settings.EMAIL_HOST_USER),
        f'host={settings.EMAIL_HOST} user={settings.EMAIL_HOST_USER}',
    )

    print()
    print('========== SUMMARY ==========')
    passed = sum(1 for s, _, __ in results if s == 'PASS')
    failed = sum(1 for s, _, __ in results if s == 'FAIL')
    print(f'PASS={passed} FAIL={failed} TOTAL={len(results)}')
    for s, n, d in results:
        if s == 'FAIL':
            print(f'  FAIL: {n} — {d}')
    return 0 if failed == 0 else 1


if __name__ == '__main__':
    raise SystemExit(main())
