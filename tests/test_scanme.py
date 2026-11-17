from pathlib import Path

from rag_verify_lab.scan import nmap_runner
from rag_verify_lab.scan.nuclei_runner import run_nuclei


def test_scanme_resolves_without_target_restriction(monkeypatch) -> None:
    monkeypatch.setattr(nmap_runner.socket, "gethostbyname", lambda _: "203.0.113.10")
    assert nmap_runner.target_ip("scanme.nmap.org") == ("scanme.nmap.org", "203.0.113.10")


def test_scanme_nuclei_is_not_invoked(monkeypatch) -> None:
    def fail(*args, **kwargs):
        raise AssertionError("Nuclei must not be invoked")

    monkeypatch.setattr("rag_verify_lab.scan.nuclei_runner.subprocess.run", fail)
    assert run_nuclei("scanme.nmap.org") == []


def test_scanme_nmap_command_is_low_rate_and_not_aggressive(monkeypatch) -> None:
    monkeypatch.setattr(nmap_runner.socket, "gethostbyname", lambda _: "203.0.113.10")
    calls = []

    class Completed:
        returncode = 0

    def fake_run(command, **kwargs):
        calls.append(command)
        output = Path(command[command.index("-oX") + 1])
        output.write_text(
            '<nmaprun><host><address addr="203.0.113.10"/></host></nmaprun>',
            encoding="utf-8",
        )
        return Completed()

    monkeypatch.setattr(nmap_runner.subprocess, "run", fake_run)
    result = nmap_runner.run_nmap_result("scanme.nmap.org", "1-1000")
    command = result.command
    assert "-T2" in command
    assert "-sT" in command and "-sV" in command
    assert "-A" not in command and "--script" not in command
    assert calls == [command]
