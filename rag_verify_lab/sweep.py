from __future__ import annotations

import time

from .config import settings
from .db import VM, db_session
from .scan.nmap_runner import run_nmap
from .scan.wait import wait_for_port
from .vms import container_start, container_stop, image_pull


def run_sweep(vm_ids: list[int], cancelled=None) -> str:
    completed = 0
    for vm_id in vm_ids:
        if cancelled and cancelled():
            break
        with db_session() as db:
            vm = db.get(VM, vm_id)
            if not vm:
                continue
            ref, host, port, target_range = vm.image_ref, vm.host_port, vm.container_port, vm.port_range
        try:
            image_pull(ref)
            container_start(vm_id)
            with db_session() as db:
                host = db.get(VM, vm_id).host_port
            if not host or not wait_for_port("127.0.0.1", host, settings.container_wait_seconds):
                raise TimeoutError("Container port did not become ready")
            run_nmap("127.0.0.1", str(host))
            completed += 1
        except Exception:
            pass
        finally:
            try:
                container_stop(vm_id)
            except Exception:
                pass
            time.sleep(settings.sweep_cooldown_seconds)
    return f"{completed}/{len(vm_ids)} sweep steps completed"
