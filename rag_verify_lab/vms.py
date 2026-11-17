from __future__ import annotations

import socket
import subprocess
import uuid
from typing import Any

from .db import Image, VM, db_session


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def add_vm(data: dict[str, Any]) -> VM:
    with db_session() as db:
        vm = VM(**data, host_port=None, status="stopped")
        db.add(vm)
        db.commit()
        db.refresh(vm)
        return vm


def container_start(vm_id: int) -> str:
    with db_session() as db:
        vm = db.get(VM, vm_id)
        if not vm:
            raise ValueError("VM not found")
        port = free_port()
        name = f"rag-lab-{vm.id}-{uuid.uuid4().hex[:8]}"
        subprocess.run(["docker", "run", "-d", "-p", f"{port}:{vm.container_port}", "--name", name, vm.image_ref], check=True, capture_output=True, text=True)
        vm.host_port, vm.status, vm.container_name = port, "running", name
        db.commit()
    return f"Started on host port {port}"


def container_stop(vm_id: int) -> str:
    with db_session() as db:
        vm = db.get(VM, vm_id)
        if not vm:
            raise ValueError("VM not found")
        if vm.container_name:
            subprocess.run(["docker", "stop", vm.container_name], check=False, capture_output=True)
            subprocess.run(["docker", "rm", vm.container_name], check=False, capture_output=True)
        vm.status, vm.host_port, vm.container_name = "stopped", None, None
        db.commit()
    return "Stopped"


def image_list() -> list[Image]:
    with db_session() as db:
        return list(db.query(Image).order_by(Image.ref).all())


def image_pull(ref: str) -> str:
    subprocess.run(["docker", "pull", ref], check=True, capture_output=True, text=True)
    with db_session() as db:
        image = db.get(Image, ref)
        if image:
            image.pulled = True
        else:
            db.add(Image(ref=ref, description="", pulled=True))
        db.commit()
    return "Pulled"
