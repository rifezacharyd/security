from zdr_honeypot_feed.signing import sign, verify


def test_roundtrip() -> None:
    key = "test-key"
    body = b'{"hello":"world"}'
    sig = sign(body, key)
    assert sig.startswith("sha256=")
    assert verify(body, sig, key)


def test_tamper_detection() -> None:
    key = "test-key"
    body = b'{"hello":"world"}'
    sig = sign(body, key)
    assert not verify(b'{"hello":"mars"}', sig, key)
    assert not verify(body, sig, "different-key")
