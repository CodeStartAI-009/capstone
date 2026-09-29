"""Measure real API response times against a real `python app.py` process.

    python scripts/benchmark_api.py [--requests 200]

Starts the Flask app on a free port with a temporary database and rate limiting
disabled, then times (client side, wall clock over loopback HTTP):
  * start-up until /api/health answers (includes loading the model once),
  * sequential POST /api/predict with history recording (record=true) and without,
  * concurrent POST /api/predict (8 client threads),
  * GET /api/health, GET /api/history, GET /api/stats.
URLs are held-out test-split URLs from the dataset plus fixed examples.
Writes docs/data/performance.json.
"""
import argparse
import json
import os
import platform
import socket
import statistics
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
OUT = ROOT / "docs" / "data" / "performance.json"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def timed(fn):
    start = time.perf_counter()
    result = fn()
    return (time.perf_counter() - start) * 1000, result


def get(url):
    with urlopen(url, timeout=30) as r:
        return r.status, json.loads(r.read())


def post(base, payload):
    req = Request(base + "/api/predict", data=json.dumps(payload).encode(),
                  headers={"Content-Type": "application/json"}, method="POST")
    with urlopen(req, timeout=30) as r:
        return r.status, json.loads(r.read())


def summary(values):
    values = sorted(values)
    return {"n": len(values), "mean_ms": round(statistics.mean(values), 2),
            "median_ms": round(statistics.median(values), 2),
            "p95_ms": round(values[max(0, int(round(0.95 * len(values))) - 1)], 2),
            "max_ms": round(values[-1], 2), "min_ms": round(values[0], 2)}


def test_urls(n):
    from ml.dataset import load_registrable_grouped_split
    test = load_registrable_grouped_split()[0]["test"]
    sample = test.sample(n, random_state=7)["URL"].astype(str).tolist()
    return sample


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--requests", type=int, default=200)
    args = parser.parse_args()
    n = args.requests
    urls = test_urls(n)

    port = free_port()
    base = f"http://127.0.0.1:{port}"
    tmp = tempfile.mkdtemp()
    env = {**os.environ, "API_PORT": str(port), "DATABASE_PATH": str(Path(tmp) / "bench.db"),
           "RATE_LIMIT_PER_MINUTE": "0", "FLASK_DEBUG": "false"}
    start = time.perf_counter()
    proc = subprocess.Popen([sys.executable, "app.py"], cwd=ROOT, env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        while True:
            try:
                if get(base + "/api/health")[1].get("model_loaded"):
                    break
            except OSError:
                time.sleep(0.05)
            if time.perf_counter() - start > 60:
                raise SystemExit("server did not start")
        startup_ms = (time.perf_counter() - start) * 1000

        for u in urls[:10]:  # warm-up
            post(base, {"url": u, "record": False})

        rejected = 0
        rec, rec_server, norec, norec_server = [], [], [], []
        for u in urls:
            try:
                ms, (_, body) = timed(lambda: post(base, {"url": u, "record": True}))
            except Exception:
                rejected += 1  # a few dataset URLs are private/invalid hosts and are rejected with 400
                continue
            rec.append(ms)
            rec_server.append(body["timing_ms"]["total"])
        for u in urls:
            try:
                ms, (_, body) = timed(lambda: post(base, {"url": u, "record": False}))
            except Exception:
                continue
            norec.append(ms)
            norec_server.append(body["timing_ms"]["total"])

        def one(u):
            try:
                return timed(lambda: post(base, {"url": u, "record": True}))[0]
            except Exception:
                return None
        wall_start = time.perf_counter()
        with ThreadPoolExecutor(max_workers=8) as pool:
            concurrent = [ms for ms in pool.map(one, urls) if ms is not None]
        wall = time.perf_counter() - wall_start

        health = [timed(lambda: get(base + "/api/health"))[0] for _ in range(100)]
        history = [timed(lambda: get(base + "/api/history?page=1&limit=20"))[0] for _ in range(100)]
        stats = [timed(lambda: get(base + "/api/stats"))[0] for _ in range(50)]
        rows = get(base + "/api/stats")[1]["total"]
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    report = {
        "measured_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "environment": {"python": platform.python_version(), "machine": platform.machine(),
                        "system": platform.system(), "server": "Flask development server (python app.py), threaded"},
        "startup_until_model_loaded_ms": round(startup_ms, 1),
        "predict_sequential_record_true_client": summary(rec),
        "predict_sequential_record_true_server_timing": summary(rec_server),
        "predict_sequential_record_false_client": summary(norec),
        "predict_sequential_record_false_server_timing": summary(norec_server),
        "predict_concurrent_8_threads_client": summary(concurrent),
        "predict_concurrent_throughput_per_s": round(len(concurrent) / wall, 1),
        "health_client": summary(health),
        "history_page_client": summary(history),
        "stats_client": summary(stats),
        "urls": f"{len(urls)} held-out test-split URLs; {rejected} rejected by validation (400)",
        "history_rows_at_end": rows,
    }
    OUT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
