# Foundly — Campus Lost & Found

## Open the website

Open `index.html` directly in a browser. The frontend is self-contained and does not require npm, a dev server, or an internet connection for its functionality. Google Fonts are optional; the page falls back to system fonts.

Search and category filters, lost/found tabs, saved reports, report submission, detail views, and browser persistence are all handled in the page. Submitted reports are saved in the browser's local storage.

## Optional API

The FastAPI + SQLite backend is in `backend/`. Install `backend/requirements.txt`, then start it with `python -m uvicorn backend.main:app --reload`. The API explorer is available at `/docs`.
