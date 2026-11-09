from socforge.security import sign_payload, verify_payload


def test_hmac_signature_roundtrip():
    body = b'{"event_type":"authentication_success"}'
    signature = sign_payload(body, "test-secret")
    assert verify_payload(body, signature, "test-secret")
    assert not verify_payload(body + b" ", signature, "test-secret")
    assert not verify_payload(body, "invalid", "test-secret")
