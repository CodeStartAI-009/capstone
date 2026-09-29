"""Entry point: web UI + REST API for phishing URL detection.

    python app.py
"""
import os

# Must run before scikit-learn loads its OpenMP runtime; see ML_THREADS in config.py.
if os.environ.get("ML_THREADS", "1") != "0":
    os.environ.setdefault("OMP_NUM_THREADS", os.environ.get("ML_THREADS", "1"))

from backend import create_app  # noqa: E402

app = create_app()

if __name__ == "__main__":
    app.run(host=app.config["API_HOST"], port=app.config["API_PORT"], debug=app.config["DEBUG"])
