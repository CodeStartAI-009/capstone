# Phishing URL Scanner: Chrome extension (Manifest V3)

Checks the current tab's URL with the project's Flask API when you click the icon.
It has no model of its own; every result comes from `POST /api/predict`.

1. Start the API: `python app.py` (http://127.0.0.1:5000).
2. `chrome://extensions` → Developer mode → **Load unpacked** → select this folder.
3. Open a web page and click the toolbar icon.

The API location is set in **`config.js`** (`API_BASE`) and must match `host_permissions` in
`manifest.json`. Permissions: `activeTab` plus the API origin only.

Full documentation: [`../docs/extension.md`](../docs/extension.md).
