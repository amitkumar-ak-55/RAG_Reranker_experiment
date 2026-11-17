from rag_verify_lab.scan.wait import wait_for_port


def test_port_wait_timeout() -> None:
    assert not wait_for_port("127.0.0.1", 1, 0.05, 0.01)
