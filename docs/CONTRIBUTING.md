# Feedback & Issues

MailGuard is free to use but not open source. The source code is shared for transparency and self-hosting purposes.

## Reporting Bugs

Please open a GitHub issue with:
- A clear description of the bug
- Steps to reproduce
- Expected vs. actual behavior
- Your deployment environment (local Docker, Azure, etc.)

## Feature Requests

Open a GitHub issue with the label `enhancement`. Describe the use case and what problem it solves.

## Development Setup (for self-hosting)

### Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your credentials
uvicorn app.main:app --reload --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev   # http://localhost:5173 (proxies /api to :8000)
```

### With Docker

```bash
docker compose up --build
```

## License

Free to use for personal and internal business purposes. Redistribution, modification, and use in competing products is not permitted without written permission. See [LICENSE](../LICENSE).
