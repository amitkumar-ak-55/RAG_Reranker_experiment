from __future__ import annotations

from rag_verify_lab import cli


def test_scan_requires_authorized(capsys) -> None:
    assert cli.main(["scan", "192.0.2.1"]) == 2
    assert cli.AUTHORIZATION_MESSAGE in capsys.readouterr().err


def test_scan_rejects_invalid_target(capsys) -> None:
    assert cli.main(["scan", "not a target", "--authorized"]) == 2
    assert "valid IPv4 address" in capsys.readouterr().err


def test_scanme_rejects_nuclei(capsys) -> None:
    assert cli.main(["scan", "scanme.nmap.org", "--authorized", "--tools", "nmap,nuclei"]) == 2
    assert "Refusing to run nuclei" in capsys.readouterr().err


def test_check_jev_exit_codes(monkeypatch, capsys) -> None:
    passing = {
        "configured": True,
        "reachable": True,
        "authenticated": True,
        "model_accepted": True,
        "error_message": "",
    }
    monkeypatch.setattr(cli, "jev_health", lambda: passing)
    assert cli.main(["check-jev"]) == 0
    assert "configured: pass" in capsys.readouterr().out

    failing = dict(passing, model_accepted=False, error_message="rejected")
    monkeypatch.setattr(cli, "jev_health", lambda: failing)
    assert cli.main(["check-jev"]) == 1
    assert "model_accepted: fail" in capsys.readouterr().out
