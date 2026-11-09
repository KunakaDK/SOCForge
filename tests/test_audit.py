from socforge.audit import append_audit, verify_audit_chain
from socforge.db import init_db, connect


def test_audit_chain_verifies_and_detects_tampering(tmp_path):
    db_path = str(tmp_path / "socforge.db")
    init_db(db_path)
    append_audit("analyst", "test.action", "test", "1", {"x": 1}, db_path)
    append_audit("analyst", "test.action", "test", "2", {"x": 2}, db_path)
    assert verify_audit_chain(db_path)["valid"] is True
    conn = connect(db_path)
    conn.execute("UPDATE audit_log SET details_json='{}' WHERE id=1")
    conn.commit()
    conn.close()
    assert verify_audit_chain(db_path)["valid"] is False
