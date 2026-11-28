# SPDX-License-Identifier: LGPL-3.0-only
"""Backend commands for the historical Python daemon."""
import os
from pathlib import Path
import subprocess


def image_deletion_command():
    return ['/usr/bin/php', str(Path(__file__).resolve().with_name('cli') / 'delete-image.php')]


def prepare_preset_import():
    cli_script = Path(__file__).resolve().with_name('cli') / 'preset-import.php'
    if not cli_script.is_file():
        raise RuntimeError(f"CLI introuvable : {cli_script}")

    def run(path):
        return subprocess.run(
            ['php', str(cli_script), f'--json-file={path}'],
            capture_output=True, text=True, timeout=30,
        )

    return run


def run_nginx_reload_job(job: dict, update_init_job, now) -> None:
    """Handler init_job 'system:nginx_reload' — hot-reload de la conf nginx
    admin après changement de la setting `https_enabled` côté UI.

    Pipeline :
      1. Re-exécute /opt/pxe-tools/init/render-nginx-conf.sh (re-render des
         fichiers admin-https.conf + admin-http.conf selon la setting actuelle)
      2. `nginx -t` valide la conf rendue
      3. `nginx -s reload` applique sans downtime (sockets actifs conservés)
      4. Si validation échoue, on ne reload pas — la conf précédente reste
         active (état nginx non touché). Le job est marqué failed.

    Le worker tourne root → accès direct aux scripts shell et signaux nginx,
    pas besoin de docker exec.
    """
    job_id = job["id"]
    update_init_job(job_id, status="running", started_at=now(), updated_at=now())

    log_buffer: list[str] = []

    def _log(msg: str) -> None:
        log_buffer.append(msg)

    # Native installation can use a separate nginx master and configuration.
    # The default remains the appliance's existing nginx process.
    nginx_config = os.environ.get("PXE_NGINX_CONFIG", "").strip()
    if nginx_config and not os.path.isabs(nginx_config):
        update_init_job(job_id, status="failed", ended_at=now(), updated_at=now(),
                        message="Chemin de configuration nginx absolu requis.")
        return
    nginx_config_args = ["-c", nginx_config] if nginx_config else []

    # 1. Re-render
    try:
        rr = subprocess.run(
            ["/opt/pxe-tools/init/render-nginx-conf.sh"],
            capture_output=True, text=True, timeout=10,
        )
    except Exception as e:
        update_init_job(job_id, status="failed", ended_at=now(), updated_at=now(),
                        message=f"render-nginx-conf exception : {e}",
                        log="".join(log_buffer))
        return
    _log(f"[render-nginx-conf rc={rr.returncode}]\n{rr.stdout}{rr.stderr}\n")
    if rr.returncode != 0:
        update_init_job(job_id, status="failed", ended_at=now(), updated_at=now(),
                        message=f"render-nginx-conf KO (rc={rr.returncode})",
                        log="".join(log_buffer))
        return

    # 2. Validation conf
    try:
        nt = subprocess.run(
            ["nginx", "-t", *nginx_config_args],
            capture_output=True, text=True, timeout=10,
        )
    except Exception as e:
        update_init_job(job_id, status="failed", ended_at=now(), updated_at=now(),
                        message=f"nginx -t exception : {e}",
                        log="".join(log_buffer))
        return
    _log(f"[nginx -t rc={nt.returncode}]\n{nt.stdout}{nt.stderr}\n")
    if nt.returncode != 0:
        update_init_job(job_id, status="failed", ended_at=now(), updated_at=now(),
                        message=f"nginx -t KO (rc={nt.returncode}) — reload annulé, conf précédente conservée",
                        log="".join(log_buffer))
        return

    # 3. Reload (SIGHUP-like, zero downtime)
    try:
        rl = subprocess.run(
            ["nginx", "-s", "reload", *nginx_config_args],
            capture_output=True, text=True, timeout=10,
        )
    except Exception as e:
        update_init_job(job_id, status="failed", ended_at=now(), updated_at=now(),
                        message=f"nginx -s reload exception : {e}",
                        log="".join(log_buffer))
        return
    _log(f"[nginx -s reload rc={rl.returncode}]\n{rl.stdout}{rl.stderr}\n")
    if rl.returncode != 0:
        update_init_job(job_id, status="failed", ended_at=now(), updated_at=now(),
                        message=f"nginx -s reload KO (rc={rl.returncode})",
                        log="".join(log_buffer))
        return

    update_init_job(job_id, status="success", ended_at=now(), updated_at=now(),
                    message="Conf nginx admin re-rendue et reload appliqué (zero downtime)",
                    log="".join(log_buffer))
