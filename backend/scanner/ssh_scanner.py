import paramiko
import requests as req
import json
import re
import shlex
import os
import logging
import time

from django.conf import settings

from .scan_cancellation import ScanCancelled

logger = logging.getLogger(__name__)

def get_ssh_client():
    missing = [
        name for name in ('SSH_HOST', 'SSH_USER', 'SSH_PASSWORD')
        if not str(getattr(settings, name, '') or '').strip()
    ]
    if missing:
        raise RuntimeError(f"Configuration SSH incomplete: {', '.join(missing)}")

    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    if settings.SSH_AUTO_ADD_HOST_KEY:
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    else:
        ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
    ssh.connect(
        hostname=settings.SSH_HOST,
        port=settings.SSH_PORT,
        username=settings.SSH_USER,
        password=settings.SSH_PASSWORD,
        timeout=settings.SSH_CONNECT_TIMEOUT,
        auth_timeout=settings.SSH_CONNECT_TIMEOUT,
        banner_timeout=settings.SSH_CONNECT_TIMEOUT,
    )
    return ssh


def parse_target(target):
    """
    Sépare host et port si présents.
    Retourne (host, port) où port est un int ou None si absent.
    Gère : nom de domaine seul, IP seule, host:port, IP:port.
    Ne pas confondre avec les IPv6 (pas de support IPv6 requis pour l'instant).
    """
    host = (target or '').strip()
    port = None
    # Une adresse IPv6 contient plusieurs ':' : on ne tente pas d'extraire un
    # port dans ce cas (IPv6 non supporté pour l'instant).
    if host.count(':') == 1:
        candidate_host, _, candidate_port = host.partition(':')
        if candidate_host and candidate_port.isdigit():
            host = candidate_host
            port = int(candidate_port)
    return host, port


def classify_error(output, target):
    """Détecte le type d'erreur précis pour le rapport"""
    out = output.lower()
    if 'name or service not known' in out or 'could not resolve' in out or 'unknown host' in out:
        return f"DOMAINE INTROUVABLE: '{target}' n'existe pas (erreur DNS)"
    if 'connection refused' in out:
        return f"PORT FERMÉ: '{target}' refuse la connexion"
    if 'timed out' in out or 'timeout' in out:
        return f"TIMEOUT: '{target}' ne répond pas (injoignable ou pare-feu)"
    if 'no route to host' in out:
        return f"HÔTE INJOIGNABLE: '{target}' n'est pas accessible"
    return None


def run_sslscan(target, port=None, max_attempts=3, cancel_check=None):
    endpoint = f"{target}:{port}" if port else target
    command_timeout = max(int(settings.SSH_COMMAND_TIMEOUT), 1)
    command = (
        f"timeout --signal=TERM --kill-after=5s {command_timeout}s "
        f"sslscan --ipv4 --timeout=3 --connect-timeout=10 --no-colour "
        f"{shlex.quote(endpoint)}"
    )
    last_error = None
    last_raw = ''

    for attempt in range(1, max_attempts + 1):
        ssh = None
        try:
            ssh = get_ssh_client()
            result, err, exit_code = _run_ssh_command(
                ssh,
                command,
                timeout=command_timeout + 10,
                cancel_check=cancel_check,
            )
            combined = result + err
            if exit_code == 124:
                return {
                    'success': False,
                    'error': (
                        f"TIMEOUT: sslscan n'a pas terminé l'analyse de '{target}' "
                        f"en {command_timeout} secondes"
                    ),
                    'raw': combined,
                }
            error_type = classify_error(combined, target)
            last_raw = combined
            last_error = error_type or ('Aucune réponse du serveur SSL' if not result.strip() else None)

            if last_error is None:
                return {'success': True, 'error': None, 'raw': result}

            retryable = (
                last_error.startswith('TIMEOUT:')
                or last_error == 'Aucune réponse du serveur SSL'
            )
            if not retryable or attempt == max_attempts:
                return {'success': False, 'error': last_error, 'raw': combined}

            logger.warning(
                'sslscan_retry target=%s attempt=%s/%s error=%s',
                target, attempt, max_attempts, last_error,
            )
            time.sleep(2 * attempt)
        except paramiko.AuthenticationException:
            return {
                'success': False,
                'error': 'Erreur SSH: authentification VM échouée',
                'raw': last_raw,
            }
        except ScanCancelled:
            raise
        except Exception as exc:
            last_error = f'Erreur connexion VM: {str(exc)}'
            if attempt == max_attempts:
                return {'success': False, 'error': last_error, 'raw': last_raw}
            logger.warning(
                'sslscan_retry target=%s attempt=%s/%s error=%s',
                target, attempt, max_attempts, last_error,
            )
            time.sleep(2 * attempt)
        finally:
            if ssh is not None:
                try:
                    ssh.close()
                except Exception:
                    pass

    return {
        'success': False,
        'error': last_error or 'Aucune réponse du serveur SSL',
        'raw': last_raw,
    }


def run_nmap(target, port=None):
    scan_port = port or 443
    try:
        ssh = get_ssh_client()
        _, stdout, stderr = ssh.exec_command(
            f"nmap --script ssl-enum-ciphers -p {scan_port} --host-timeout 15s {target}"
        )
        result = stdout.read().decode()
        ssh.close()

        out_lower = result.lower()
        if 'host seems down' in out_lower or '0 hosts up' in out_lower:
            return {'success': False, 'error': f"HÔTE INJOIGNABLE: '{target}' semble injoignable", 'raw': result}
        if 'closed' in out_lower and 'open' not in out_lower:
            return {'success': False, 'error': f"PORT FERMÉ: {scan_port} fermé sur '{target}'", 'raw': result}
        return {'success': True, 'error': None, 'raw': result}
    except Exception as e:
        return {'success': False, 'error': str(e), 'raw': ''}


def run_openssl(target, port=None):
    connect_port = port or 443
    try:
        ssh = get_ssh_client()
        _, stdout, stderr = ssh.exec_command(
            f"timeout 10 openssl s_client -connect {target}:{connect_port} -servername {target} </dev/null 2>&1"
        )
        result = stdout.read().decode()
        ssh.close()

        error_type = classify_error(result, target)
        if error_type:
            return {'success': False, 'error': error_type, 'raw': result}
        return {'success': True, 'error': None, 'raw': result}
    except Exception as e:
        return {'success': False, 'error': str(e), 'raw': ''}


def run_whatweb(target, port=None):
    """Detect web technologies with WhatWeb running on the scanner VM."""
    technologies = {}

    try:
        clean_target = target.strip()
        if not clean_target:
            return {'success': False, 'error': 'Cible WhatWeb vide', 'technologies': []}

        # WhatWeb accepts either a URL or a hostname.  Quote it before it is
        # passed to the remote shell to keep the SSH command safe.
        host = clean_target if not port else f'{clean_target}:{port}'
        url = clean_target if clean_target.startswith(('http://', 'https://')) else f'https://{host}'
        report_path = f'/tmp/whatweb_{os.getpid()}_{abs(hash(url)) % 100000}.json'
        quoted_report = shlex.quote(report_path)
        command = (
            f'rm -f {quoted_report}; '
            f'/home/chaima/WhatWeb/whatweb -a 3 --log-json={quoted_report} --no-errors '
            f'{shlex.quote(url)} >/dev/null; '
            f'status=$?; cat {quoted_report} 2>/dev/null; '
            f'rm -f {quoted_report}; exit $status'
        )

        ssh = get_ssh_client()
        _, stdout, stderr = ssh.exec_command(command, timeout=120)
        raw_output = stdout.read().decode(errors='replace')
        err = stderr.read().decode(errors='replace')
        exit_status = stdout.channel.recv_exit_status()
        ssh.close()

        if 'not found' in err.lower() or 'command not found' in err.lower():
            return {'success': False, 'error': 'WhatWeb non installe sur la VM', 'technologies': []}

        # --log-json=- outputs JSON records.  Ignore banners or other lines
        # that are not valid JSON, as requested.
        for line in raw_output.splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            records = record if isinstance(record, list) else [record]
            for item in records:
                if not isinstance(item, dict):
                    continue
                plugins = item.get('plugins', {})
                if not isinstance(plugins, dict):
                    continue
                for name, data in plugins.items():
                    if not isinstance(data, dict):
                        data = {}
                    technology = technologies.setdefault(name, {
                        'name': name,
                        'version': [],
                        'string': [],
                    })
                    for field in ('version', 'string'):
                        values = data.get(field, [])
                        if not isinstance(values, list):
                            values = [values]
                        for value in values:
                            if value not in (None, '') and value not in technology[field]:
                                technology[field].append(value)

        if exit_status != 0:
            return {
                'success': False,
                'error': err.strip() or f'WhatWeb a termine avec le code {exit_status}',
                'technologies': list(technologies.values()),
            }

        return {'success': True, 'technologies': list(technologies.values())}
    except Exception as e:
        error = str(e).strip() or e.__class__.__name__
        return {'success': False, 'error': f'Erreur execution WhatWeb: {error}', 'technologies': []}


def run_ssllabs(target):
    try:
        url = f"https://api.ssllabs.com/api/v3/analyze?host={target}&publish=off&all=done"
        response = req.get(url, timeout=60)
        data = response.json()

        status = data.get('status', 'UNKNOWN')

        if status == 'READY':
            endpoints = data.get('endpoints', [])
            if endpoints:
                grade = endpoints[0].get('grade', 'N/A')
                return {'success': True, 'status': 'ready', 'grade': grade, 'host': target}
            return {'success': False, 'status': 'no_endpoints', 'grade': 'N/A', 'host': target}

        if status == 'IN_PROGRESS':
            return {'success': True, 'status': 'in_progress', 'grade': 'EN COURS...', 'host': target}

        if status == 'ERROR':
            return {'success': False, 'status': 'error', 'grade': 'N/A',
                    'error': f"SSL Labs ne peut analyser '{target}' (domaine introuvable ou injoignable)"}

        return {'success': False, 'status': status.lower(), 'grade': 'N/A', 'host': target}

    except req.exceptions.Timeout:
        return {'success': False, 'status': 'timeout', 'grade': 'N/A', 'error': 'SSL Labs API timeout'}
    except Exception as e:
        return {'success': False, 'status': 'error', 'grade': 'N/A', 'error': str(e)}


def run_nuclei(target, port=None):
    def parse_nuclei_output(output):
        findings = []

        # Some older Nuclei versions use -json and emit one JSON array instead
        # of JSONL.  Handle that format before falling back to line-by-line
        # parsing.
        try:
            parsed_output = json.loads(output)
            if isinstance(parsed_output, dict):
                parsed_output = [parsed_output]
            if isinstance(parsed_output, list):
                for finding in parsed_output:
                    if not isinstance(finding, dict):
                        continue
                    findings.append({
                        'template_id': finding.get('template-id', ''),
                        'name': finding.get('info', {}).get('name', ''),
                        'severity': finding.get('info', {}).get('severity', 'info').lower(),
                        'description': finding.get('info', {}).get('description', ''),
                        'matched_at': finding.get('matched-at') or finding.get('host', ''),
                    })
                return findings
        except (TypeError, json.JSONDecodeError):
            pass

        for line in output.strip().splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                finding = json.loads(line)
                findings.append({
                    'template_id': finding.get('template-id', ''),
                    'name': finding.get('info', {}).get('name', ''),
                    'severity': finding.get('info', {}).get('severity', 'info'),
                    'description': finding.get('info', {}).get('description', ''),
                    'matched_at': finding.get('matched-at') or finding.get('host', ''),
                })
                continue
            except json.JSONDecodeError:
                pass

            match = re.match(
                r'^\[(?P<template>[^\]]+)\]\s+\[[^\]]+\]\s+\[(?P<severity>[^\]]+)\]\s+(?P<matched>.+)$',
                line
            )
            if match:
                template_id = match.group('template')
                findings.append({
                    'template_id': template_id,
                    'name': template_id.replace('-', ' ').title(),
                    'severity': match.group('severity').lower(),
                    'description': line,
                    'matched_at': match.group('matched').strip(),
                })

        return findings

    try:
        clean_target = target.strip()
        if not clean_target:
            return {'success': False, 'error': 'Cible Nuclei vide', 'findings': [], 'raw': ''}

        host = clean_target if not port else f'{clean_target}:{port}'
        url = clean_target if clean_target.startswith('http') else f'https://{host}'
        quoted_url = shlex.quote(url)
        ssh = get_ssh_client()

        # Run only the HTTP templates needed by this application.  This keeps
        # the scan within the remote timeout instead of running every locally
        # installed Nuclei template.
        base_command = (
            f"timeout 90s nuclei -u {quoted_url} -silent -timeout 5 -no-color "
            f"-t http/technologies/tech-detect.yaml,http/exposures/,http/cves/ "
            f"-severity critical,high,medium -rate-limit 100 -c 25"
        )

        _, stdout, stderr = ssh.exec_command(f"{base_command} -jsonl", timeout=110)
        raw_output = stdout.read().decode()
        err = stderr.read().decode()
        exit_status = stdout.channel.recv_exit_status()

        if 'flag provided but not defined' in err.lower() and 'jsonl' in err.lower():
            _, stdout, stderr = ssh.exec_command(f"{base_command} -json", timeout=110)
            raw_output = stdout.read().decode()
            err = stderr.read().decode()
            exit_status = stdout.channel.recv_exit_status()

        ssh.close()

        combined_output = '\n'.join(part for part in (raw_output, err) if part)
        if 'not found' in err.lower() or 'command not found' in err.lower():
            return {'success': False, 'error': 'Nuclei non installe sur le VM', 'findings': [], 'raw': err}

        # Nuclei normally writes findings to stdout, but collecting both
        # streams preserves findings from wrappers or older installations.
        findings = parse_nuclei_output(combined_output)
        if exit_status == 124:
            return {
                'success': False,
                'error': 'Nuclei a depasse la limite de 90 secondes',
                'findings': findings,
                'raw': combined_output,
            }

        if exit_status != 0 and not findings:
            return {
                'success': False,
                'error': err.strip() or f'Nuclei a termine avec le code {exit_status}',
                'findings': [],
                'raw': combined_output,
            }

        return {'success': True, 'findings': findings, 'raw': combined_output}
    except Exception as e:
        # socket.timeout and a few Paramiko exceptions stringify to an empty
        # string.  Returning the class name makes the failure actionable.
        error = str(e).strip() or e.__class__.__name__
        return {'success': False, 'error': f'Erreur execution Nuclei: {error}', 'findings': [], 'raw': ''}


def _run_ssh_command(ssh, command, timeout=None, cancel_check=None, on_cancel=None):
    """Exécute une commande SSH en drainant ses deux flux sans interblocage."""
    _, stdout, _ = ssh.exec_command(command, timeout=timeout)
    channel = stdout.channel
    deadline = time.monotonic() + float(timeout) if timeout is not None else None
    stdout_chunks = []
    stderr_chunks = []

    while True:
        if cancel_check is not None and cancel_check():
            try:
                if on_cancel is not None:
                    on_cancel()
            finally:
                channel.close()
            raise ScanCancelled('Commande SSH interrompue par annulation du scan')

        received_data = False

        while channel.recv_ready():
            chunk = channel.recv(64 * 1024)
            if not chunk:
                break
            stdout_chunks.append(chunk)
            received_data = True

        while channel.recv_stderr_ready():
            chunk = channel.recv_stderr(64 * 1024)
            if not chunk:
                break
            stderr_chunks.append(chunk)
            received_data = True

        if channel.exit_status_ready():
            if not channel.recv_ready() and not channel.recv_stderr_ready():
                break

        if deadline is not None and time.monotonic() >= deadline:
            channel.close()
            raise TimeoutError(f'Commande SSH expirée après {timeout} secondes')

        if not received_data:
            time.sleep(0.05)

    exit_code = channel.recv_exit_status()
    out = b''.join(stdout_chunks).decode(errors='replace')
    err = b''.join(stderr_chunks).decode(errors='replace')
    return out, err, exit_code


def _stop_remote_container(container_name):
    cleanup_ssh = None
    try:
        cleanup_ssh = get_ssh_client()
        quoted_name = shlex.quote(container_name)
        _run_ssh_command(
            cleanup_ssh,
            f'docker rm -f {quoted_name} >/dev/null 2>&1 || true',
            timeout=20,
        )
    except Exception:
        logger.warning('ZAP: arrêt du conteneur %s impossible', container_name, exc_info=True)
    finally:
        if cleanup_ssh is not None:
            cleanup_ssh.close()


def _strip_html(text):
    """Nettoie les champs desc/solution de ZAP (qui contiennent du HTML)."""
    if not text:
        return ''
    text = re.sub(r'<[^>]+>', ' ', text)
    return re.sub(r'\s+', ' ', text).strip()


# Image Docker officielle OWASP ZAP. zap-baseline.py y est déjà installé.
ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"


def run_zap(target, timeout=600, port=None, cancel_check=None):
    """Scan web passif avec OWASP ZAP (zap-baseline.py) via Docker sur la VM.

    Le scan baseline lance un spider puis un scan passif, puis exporte un
    rapport JSON. On lit ce rapport et on renvoie les alertes normalisées.

    Retour: {'success', 'findings', 'raw', 'error'}
    findings = [{'name', 'risk', 'url', 'description', 'solution', 'count'}]
    """
    ssh = None
    try:
        clean_target = target.strip()
        if not clean_target:
            return {'success': False, 'error': 'Cible ZAP vide', 'findings': [], 'raw': ''}

        host = clean_target if not port else f'{clean_target}:{port}'
        url = clean_target if clean_target.startswith(('http://', 'https://')) else f'https://{host}'
        quoted_url = shlex.quote(url)
        job_id = getattr(cancel_check, 'scan_id', None) or f'{os.getpid()}-{abs(hash(clean_target)) % 100000}'
        container_name = f'cyberscan-zap-{job_id}'

        ssh = get_ssh_client()

        # 1) Vérifier que Docker est disponible sur la VM.
        _, _, docker_code = _run_ssh_command(ssh, "command -v docker", timeout=15)
        if docker_code != 0:
            logger.error("ZAP: Docker non installé sur la VM %s", settings.SSH_HOST)
            return {'success': False, 'error': 'Docker non installé sur la VM', 'findings': [], 'raw': ''}

        # 2) Préparer un dossier de rapport ACCESSIBLE EN ÉCRITURE par
        #    l'utilisateur "zap" (uid 1000) du conteneur. chmod 777 corrige
        #    l'erreur silencieuse "Permission denied" à l'écriture du rapport.
        report_dir = "/tmp/zap-reports"
        report_name = f"zap_{os.getpid()}_{abs(hash(clean_target)) % 100000}.json"
        _run_ssh_command(ssh, f"mkdir -p {report_dir} && chmod 777 {report_dir}", timeout=30)

        # 3) Pré-télécharger l'image : le PREMIER pull (~1 Go) dépasse souvent
        #    le timeout du scan lui-même et faisait échouer run_zap silencieusement.
        logger.info("ZAP: préparation de l'image %s", ZAP_IMAGE)
        pull_timeout = max(int(timeout), 1)
        image = shlex.quote(ZAP_IMAGE)
        pull_command = (
            f"docker image inspect {image} >/dev/null 2>&1 || "
            f"timeout {pull_timeout}s docker pull --quiet {image}"
        )
        _, pull_error, pull_code = _run_ssh_command(
            ssh, pull_command, timeout=pull_timeout + 15, cancel_check=cancel_check
        )
        if pull_code != 0:
            return {
                'success': False,
                'error': pull_error.strip() or 'Impossible de préparer l’image Docker ZAP',
                'findings': [],
                'raw': pull_error,
            }

        # 4) Lancer le scan baseline.
        #    -I : ne pas retourner un code d'échec sur les warnings
        #    -m 2 : 2 min de spider max (borne la durée)
        #    -J : rapport JSON écrit dans /zap/wrk/ (monté sur report_dir)
        logger.info("ZAP: démarrage du scan baseline sur %s", url)
        scan_cmd = (
            f"docker run --rm --name {shlex.quote(container_name)} "
            f"-v {report_dir}:/zap/wrk/:rw {ZAP_IMAGE} "
            f"zap-baseline.py -t {quoted_url} -I -m 2 -J {report_name}"
        )
        out, err, exit_code = _run_ssh_command(
            ssh,
            scan_cmd,
            timeout=timeout,
            cancel_check=cancel_check,
            on_cancel=lambda: _stop_remote_container(container_name),
        )
        # zap-baseline.py renvoie 0/1/2 selon les alertes ; on se fie au rapport
        # JSON plutôt qu'au code de sortie.
        logger.info("ZAP: scan terminé (exit=%s)", exit_code)

        # 5) Récupérer le rapport JSON, puis nettoyer.
        raw_output, cat_err, cat_code = _run_ssh_command(
            ssh, f"cat {report_dir}/{report_name}", timeout=30
        )
        _run_ssh_command(ssh, f"rm -f {report_dir}/{report_name}", timeout=15)

        if cat_code != 0 or not raw_output.strip():
            logger.error("ZAP: rapport introuvable/vide. stderr scan=%s", (err or cat_err)[:800])
            return {
                'success': False,
                'error': 'Rapport ZAP introuvable ou vide (voir logs Django)',
                'findings': [],
                'raw': out or err,
            }

        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            logger.error("ZAP: JSON invalide: %s", raw_output[:800])
            return {'success': False, 'error': 'Réponse ZAP invalide (non-JSON)', 'findings': [], 'raw': raw_output}

        findings = []
        for site in data.get('site', []):
            site_name = site.get('@name', url)
            for alert in site.get('alerts', []):
                instances = alert.get('instances', [])
                alert_url = instances[0].get('uri', site_name) if instances else site_name
                findings.append({
                    'name': alert.get('name', ''),
                    'risk': (alert.get('riskdesc', '') or '').split(' ')[0] or 'Informational',
                    'url': alert_url,
                    'description': _strip_html(alert.get('desc', '')),
                    'solution': _strip_html(alert.get('solution', '')),
                    'count': int(alert.get('count', 1) or 1),
                })

        logger.info("ZAP: %d alerte(s) trouvée(s) sur %s", len(findings), url)
        return {'success': True, 'findings': findings, 'raw': raw_output, 'error': None}

    except ScanCancelled:
        raise
    except Exception as e:
        error = str(e).strip() or e.__class__.__name__
        logger.exception("ZAP: erreur d'exécution sur %s", target)
        return {'success': False, 'error': f'Erreur exécution ZAP: {error}', 'findings': [], 'raw': ''}
    finally:
        if ssh is not None:
            try:
                ssh.close()
            except Exception:
                pass
