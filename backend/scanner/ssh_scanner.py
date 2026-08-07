import requests as req
import json
import re
import shlex
import os
import logging
import signal
import subprocess
import tempfile
import time

from django.conf import settings

from .scan_cancellation import ScanCancelled

logger = logging.getLogger(__name__)


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
    command_timeout = max(int(settings.SCANNER_COMMAND_TIMEOUT), 1)
    command = (
        f"timeout --signal=TERM --kill-after=5s {command_timeout}s "
        f"sslscan --ipv4 --timeout=3 --connect-timeout=10 --no-colour "
        f"{shlex.quote(endpoint)}"
    )
    last_error = None
    last_raw = ''

    for attempt in range(1, max_attempts + 1):
        try:
            result, err, exit_code = _run_local_command(
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
        except ScanCancelled:
            raise
        except Exception as exc:
            last_error = f'Erreur exécution locale: {str(exc)}'
            if attempt == max_attempts:
                return {'success': False, 'error': last_error, 'raw': last_raw}
            logger.warning(
                'sslscan_retry target=%s attempt=%s/%s error=%s',
                target, attempt, max_attempts, last_error,
            )
            time.sleep(2 * attempt)
    return {
        'success': False,
        'error': last_error or 'Aucune réponse du serveur SSL',
        'raw': last_raw,
    }


def run_nmap(target, port=None):
    scan_port = port or 443
    try:
        result, err, _ = _run_local_command(
            f"nmap --script ssl-enum-ciphers -p {int(scan_port)} --host-timeout 15s "
            f"{shlex.quote(target)}",
            timeout=25,
        )
        combined = result + err

        out_lower = combined.lower()
        if 'host seems down' in out_lower or '0 hosts up' in out_lower:
            return {'success': False, 'error': f"HÔTE INJOIGNABLE: '{target}' semble injoignable", 'raw': combined}
        if 'closed' in out_lower and 'open' not in out_lower:
            return {'success': False, 'error': f"PORT FERMÉ: {scan_port} fermé sur '{target}'", 'raw': combined}
        return {'success': True, 'error': None, 'raw': combined}
    except Exception as e:
        return {'success': False, 'error': str(e), 'raw': ''}


def run_openssl(target, port=None):
    connect_port = port or 443
    try:
        endpoint = shlex.quote(f'{target}:{int(connect_port)}')
        server_name = shlex.quote(target)
        result, err, _ = _run_local_command(
            f"timeout 10 openssl s_client -connect {endpoint} "
            f"-servername {server_name} </dev/null",
            timeout=15,
        )
        result += err

        error_type = classify_error(result, target)
        if error_type:
            return {'success': False, 'error': error_type, 'raw': result}
        return {'success': True, 'error': None, 'raw': result}
    except Exception as e:
        return {'success': False, 'error': str(e), 'raw': ''}


def run_whatweb(target, port=None):
    """Detect web technologies with WhatWeb installed in the worker image."""
    technologies = {}

    try:
        clean_target = target.strip()
        if not clean_target:
            return {'success': False, 'error': 'Cible WhatWeb vide', 'technologies': []}

        # WhatWeb accepts either a URL or a hostname.  Quote it before it is
        # passed to the local shell to keep the command safe.
        host = clean_target if not port else f'{clean_target}:{port}'
        url = clean_target if clean_target.startswith(('http://', 'https://')) else f'https://{host}'
        report_path = f'/tmp/whatweb_{os.getpid()}_{abs(hash(url)) % 100000}.json'
        quoted_report = shlex.quote(report_path)
        command = (
            f'rm -f {quoted_report}; '
            f'whatweb -a 3 --log-json={quoted_report} --no-errors '
            f'{shlex.quote(url)} >/dev/null; '
            f'status=$?; cat {quoted_report} 2>/dev/null; '
            f'rm -f {quoted_report}; exit $status'
        )

        raw_output, err, exit_status = _run_local_command(command, timeout=120)

        if 'not found' in err.lower() or 'command not found' in err.lower():
            return {'success': False, 'error': 'WhatWeb non installé dans le worker', 'technologies': []}

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

        # Run only the HTTP templates needed by this application.  This keeps
        # the scan within the process timeout instead of running every locally
        # installed Nuclei template.
        base_command = (
            f"timeout 90s nuclei -u {quoted_url} -silent -timeout 5 -no-color "
            f"-t http/technologies/tech-detect.yaml,http/exposures/,http/cves/ "
            f"-severity critical,high,medium -rate-limit 100 -c 25"
        )

        raw_output, err, exit_status = _run_local_command(
            f"{base_command} -jsonl",
            timeout=110,
        )

        if 'flag provided but not defined' in err.lower() and 'jsonl' in err.lower():
            raw_output, err, exit_status = _run_local_command(
                f"{base_command} -json",
                timeout=110,
            )

        combined_output = '\n'.join(part for part in (raw_output, err) if part)
        if 'not found' in err.lower() or 'command not found' in err.lower():
            return {'success': False, 'error': 'Nuclei non installé dans le worker', 'findings': [], 'raw': err}

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
        # Some process errors stringify to an empty string. Returning the
        # class name makes the failure actionable.
        error = str(e).strip() or e.__class__.__name__
        return {'success': False, 'error': f'Erreur execution Nuclei: {error}', 'findings': [], 'raw': ''}


def _terminate_process(process):
    """Stop a shell command and any scanner process started by that shell."""
    if process.poll() is not None:
        return

    try:
        if os.name == 'posix':
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
        process.wait(timeout=5)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        if process.poll() is None:
            if os.name == 'posix':
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()


def _run_local_command(command, timeout=None, cancel_check=None, on_cancel=None):
    """Run a command in the worker container with timeout and cancellation."""
    process = subprocess.Popen(
        command,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=(os.name == 'posix'),
    )
    deadline = time.monotonic() + float(timeout) if timeout is not None else None

    while True:
        if cancel_check is not None and cancel_check():
            try:
                if on_cancel is not None:
                    on_cancel()
            finally:
                _terminate_process(process)
            raise ScanCancelled('Commande locale interrompue par annulation du scan')

        if deadline is not None and time.monotonic() >= deadline:
            _terminate_process(process)
            process.communicate()
            raise TimeoutError(f'Commande locale expirée après {timeout} secondes')

        communicate_timeout = 0.1
        if deadline is not None:
            communicate_timeout = min(communicate_timeout, max(deadline - time.monotonic(), 0.001))
        try:
            out, err = process.communicate(timeout=communicate_timeout)
            return (
                out.decode(errors='replace'),
                err.decode(errors='replace'),
                process.returncode,
            )
        except subprocess.TimeoutExpired:
            continue


def _stop_local_container(container_name):
    try:
        quoted_name = shlex.quote(container_name)
        _run_local_command(
            f'docker rm -f {quoted_name} >/dev/null 2>&1 || true',
            timeout=20,
        )
    except Exception:
        logger.warning('ZAP: arrêt du conteneur %s impossible', container_name, exc_info=True)


def _remove_local_volume(volume_name):
    try:
        quoted_name = shlex.quote(volume_name)
        _run_local_command(
            f'docker volume rm -f {quoted_name} >/dev/null 2>&1 || true',
            timeout=20,
        )
    except Exception:
        logger.warning('ZAP: suppression du volume %s impossible', volume_name, exc_info=True)


def _strip_html(text):
    """Nettoie les champs desc/solution de ZAP (qui contiennent du HTML)."""
    if not text:
        return ''
    text = re.sub(r'<[^>]+>', ' ', text)
    return re.sub(r'\s+', ' ', text).strip()


# Image Docker officielle OWASP ZAP. zap-baseline.py y est déjà installé.
ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"


def run_zap(target, timeout=600, port=None, cancel_check=None):
    """Scan web passif avec OWASP ZAP via le Docker local du serveur.

    Le scan baseline lance un spider puis un scan passif, puis exporte un
    rapport JSON. On lit ce rapport et on renvoie les alertes normalisées.

    Retour: {'success', 'findings', 'raw', 'error'}
    findings = [{'name', 'risk', 'url', 'description', 'solution', 'count'}]
    """
    container_name = None
    volume_name = None
    report_path = None
    try:
        clean_target = target.strip()
        if not clean_target:
            return {'success': False, 'error': 'Cible ZAP vide', 'findings': [], 'raw': ''}

        host = clean_target if not port else f'{clean_target}:{port}'
        url = clean_target if clean_target.startswith(('http://', 'https://')) else f'https://{host}'
        quoted_url = shlex.quote(url)
        job_id = getattr(cancel_check, 'scan_id', None) or f'{os.getpid()}-{abs(hash(clean_target)) % 100000}'
        container_name = f'cyberscan-zap-{job_id}'
        volume_name = f'cyberscan-zap-work-{job_id}'

        # 1) Vérifier le client Docker et l'accès au daemon du serveur.
        _, docker_error, docker_code = _run_local_command(
            "command -v docker >/dev/null && docker version --format '{{.Server.Version}}'",
            timeout=15,
        )
        if docker_code != 0:
            logger.error("ZAP: Docker local indisponible: %s", docker_error[:800])
            return {
                'success': False,
                'error': 'Docker local indisponible dans le worker (vérifier /var/run/docker.sock)',
                'findings': [],
                'raw': docker_error,
            }

        # 2) ZAP exige que /zap/wrk soit monté avec les options de rapport.
        #    Un volume Docker temporaire évite de transmettre au daemon de
        #    l'hôte un chemin local au conteneur worker. Après le scan,
        #    `docker cp` copie le rapport depuis le conteneur ZAP arrêté.
        report_name = f"zap_{os.getpid()}_{abs(hash(clean_target)) % 100000}.json"
        report_path = os.path.join(tempfile.gettempdir(), report_name)

        # 3) Pré-télécharger l'image : le PREMIER pull (~1 Go) dépasse souvent
        #    le timeout du scan lui-même et faisait échouer run_zap silencieusement.
        logger.info("ZAP: préparation de l'image %s", ZAP_IMAGE)
        pull_timeout = max(int(timeout), 1)
        image = shlex.quote(ZAP_IMAGE)
        pull_command = (
            f"docker image inspect {image} >/dev/null 2>&1 || "
            f"timeout {pull_timeout}s docker pull --quiet {image}"
        )
        _, pull_error, pull_code = _run_local_command(
            pull_command,
            timeout=pull_timeout + 15,
            cancel_check=cancel_check,
        )
        if pull_code != 0:
            return {
                'success': False,
                'error': pull_error.strip() or 'Impossible de préparer l’image Docker ZAP',
                'findings': [],
                'raw': pull_error,
            }

        # Le volume nommé est créé par Docker avec root comme propriétaire,
        # tandis que l'image officielle exécute ZAP avec l'utilisateur `zap`.
        # Une initialisation courte en root rend /zap/wrk accessible, puis le
        # scan principal conserve l'utilisateur non privilégié de l'image.
        work_mount = shlex.quote(f'type=volume,src={volume_name},dst=/zap/wrk')
        _, volume_error, volume_code = _run_local_command(
            f"docker run --rm --user root --mount {work_mount} {image} "
            "chown zap:zap /zap/wrk",
            timeout=30,
        )
        if volume_code != 0:
            return {
                'success': False,
                'error': volume_error.strip() or 'Impossible de préparer le volume de travail ZAP',
                'findings': [],
                'raw': volume_error,
            }

        # 4) Lancer le scan baseline.
        #    -I : ne pas retourner un code d'échec sur les warnings
        #    -m 2 : 2 min de spider max (borne la durée)
        #    -J : rapport JSON écrit dans /zap/wrk/ dans le conteneur ZAP
        logger.info("ZAP: démarrage du scan baseline sur %s", url)
        scan_cmd = (
            f"docker run --name {shlex.quote(container_name)} --mount {work_mount} {image} "
            f"zap-baseline.py -t {quoted_url} -I -m 2 -J {report_name}"
        )
        out, err, exit_code = _run_local_command(
            scan_cmd,
            timeout=timeout,
            cancel_check=cancel_check,
            on_cancel=lambda: _stop_local_container(container_name),
        )
        # zap-baseline.py renvoie 0/1/2 selon les alertes ; on se fie au rapport
        # JSON plutôt qu'au code de sortie.
        logger.info("ZAP: scan terminé (exit=%s)", exit_code)

        # 5) Copier le rapport du conteneur arrêté vers le worker.
        _, copy_error, copy_code = _run_local_command(
            f"docker cp {shlex.quote(container_name)}:/zap/wrk/{shlex.quote(report_name)} "
            f"{shlex.quote(report_path)}",
            timeout=30,
        )

        if copy_code != 0 or not os.path.isfile(report_path):
            logger.error("ZAP: rapport introuvable. stderr scan=%s", (err or copy_error)[:800])
            return {
                'success': False,
                'error': 'Rapport ZAP introuvable ou vide (voir logs Django)',
                'findings': [],
                'raw': out or err,
            }

        with open(report_path, encoding='utf-8') as report_file:
            raw_output = report_file.read()
        if not raw_output.strip():
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
        if container_name is not None:
            _stop_local_container(container_name)
        if volume_name is not None:
            _remove_local_volume(volume_name)
        if report_path is not None:
            try:
                os.remove(report_path)
            except FileNotFoundError:
                pass
