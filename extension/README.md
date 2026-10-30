# Phishing URL Scanner: Chrome extension (Manifest V3)

Checks the address of each page you open with the project's Flask API: a toolbar badge shows the result and
high-risk sites get a warning page (**Go Back to Safety** / **Continue Anyway**). The popup scans the current
tab on demand. It has no model of its own; every result comes from `POST /api/predict`.

1. Start the API: `python app.py` (http://127.0.0.1:5000).
2. `chrome://extensions` → Developer mode → **Load unpacked** → select this folder.
3. Open a web page: the badge shows the automatic result. Click the toolbar icon for details and settings.

The API location is set in **`config.js`** (`API_BASE`) and must match `host_permissions` in
`manifest.json`. Permissions: `tabs`, `storage` and the API origin only. Automatic checks send only the
site's origin (e.g. `https://example.com/`), never page contents.

Full documentation: [`../docs/extension.md`](../docs/extension.md).
