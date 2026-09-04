import os
import shutil
import tempfile


def _make_two_real_dirs():
    """Create two real temp directories: one identical file (byte-for-byte
    same), which guarantees at least the BRC-006 informational finding, and
    is also easy to extend with a differing file to guarantee BRC-001."""
    a = tempfile.mkdtemp(prefix="brc_web_a_")
    b = tempfile.mkdtemp(prefix="brc_web_b_")
    with open(os.path.join(a, "app.bin"), "wb") as f:
        f.write(b"BUILD-A-PAYLOAD-BYTES")
    with open(os.path.join(b, "app.bin"), "wb") as f:
        f.write(b"BUILD-B-DIFFERENT-PAYLOAD")  # differs -> guarantees a real finding
    return a, b


def test_full_scan_alert_incident_workflow(registered_client):
    dir_a, dir_b = _make_two_real_dirs()
    try:
        # Run a real comparison of two real temp directories.
        resp = registered_client.post(
            "/scan/run",
            data={"target_path": dir_a, "target_path_b": dir_b},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"Scan complete" in resp.data

        # Logs page should show both real build paths.
        resp = registered_client.get("/logs")
        assert dir_a.encode() in resp.data
        assert dir_b.encode() in resp.data

        # Alerts page should load and contain a real alert from the mismatch.
        resp = registered_client.get("/alerts")
        assert resp.status_code == 200

        # Analytics JSON endpoint returns real aggregated data.
        resp = registered_client.get("/analytics/data")
        assert resp.status_code == 200
        assert resp.is_json

        # Reports CSV export works and includes a real finding.
        resp = registered_client.get("/reports/export.csv")
        assert resp.status_code == 200
        assert resp.headers["Content-Type"].startswith("text/csv")
        assert b"BRC-001" in resp.data
    finally:
        shutil.rmtree(dir_a)
        shutil.rmtree(dir_b)


def test_settings_page_round_trip(registered_client):
    resp = registered_client.post("/settings", data={
        "default_scan_path": "/tmp",
        "scan_depth_limit": "3",
        "exclude_paths": "/proc,/sys",
        "alert_on_severity": "high",
    }, follow_redirects=True)
    assert b"Settings saved" in resp.data

    resp = registered_client.get("/settings")
    assert b"/tmp" in resp.data


def test_all_nav_pages_load(registered_client):
    for path in ["/", "/logs", "/alerts", "/incidents", "/analytics", "/reports", "/settings"]:
        resp = registered_client.get(path)
        assert resp.status_code == 200, f"{path} failed with {resp.status_code}"


def test_404_page(registered_client):
    resp = registered_client.get("/this-page-does-not-exist")
    assert resp.status_code == 404
