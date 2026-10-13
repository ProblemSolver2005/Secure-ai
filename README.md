# Sentinel AI — Secure IT Support & Security Assistant

A beginner-friendly Django web app using HTML, CSS, SQLite, and the Groq API. It includes a responsive dashboard, incident tracking, a log analyzer, and an AI troubleshooting assistant.

## Features
- Dashboard with incident counts and recent cases
- Incident creation, search, filters, details, severity and status
- AI troubleshooting assistant powered by the Groq API
- Authentication log upload and simple event counting
- Common secret/email/IP redaction before AI text is sent to Groq
- Django login protection, CSRF protection, ORM queries, and security headers
- SQLite database, suitable for a local portfolio/demo project

## Run on Windows

1. Install Python 3.11 or newer from https://www.python.org/downloads/windows/ and enable **Add Python to PATH**.
2. Extract this folder and open it in VS Code.
3. Open Terminal > New Terminal in VS Code.
4. Create a virtual environment:

   ```bat
   py -m venv .venv
   .venv\Scripts\activate
   ```

5. Install dependencies:

   ```bat
   python -m pip install -r requirements.txt
   ```

6. Copy `.env.example` to `.env` and add your Groq API key. You can obtain/manage API access in the Groq Console at https://console.groq.com/keys. Do not share your key or commit `.env`.

   ```bat
   copy .env.example .env
   notepad .env
   ```

7. The project reads `.env` automatically when Django starts. Keep the `.env` file private.

8. Create database tables and an admin/login user:

   ```bat
   python manage.py makemigrations assistant
   python manage.py migrate
   python manage.py createsuperuser
   ```

9. Start the server:

   ```bat
   python manage.py runserver
   ```

10. Visit http://127.0.0.1:8000/ and sign in with the superuser you created.

## Groq API configuration
- Default endpoint: `https://api.x.ai/v1/chat/completions`
- Default model: `llama-3.3-70b-versatile`. If unavailable to your account, use a model ID currently listed in https://console.groq.com/docs/models and update `GROQ_MODEL`.
- Set `GROQ_API_KEY` in `.env`/environment. Never put the key in HTML, JavaScript, or source code.
- The AI features show a clear message when no key is configured or the API is unavailable.

## Important privacy and security notes
- This is a portfolio/demo app, not a production security platform.
- The app attempts to redact common password/token patterns, email addresses, and IPv4 addresses before calling Groq. Redaction is heuristic and may miss secrets; inspect and sanitize sensitive files before uploading.
- Uploaded log content is processed in memory and is not saved as an uploaded file by this app. Incident records are stored in local SQLite.
- Only upload logs you are authorized to process. Do not send regulated, customer, or production data to an external AI provider without authorization and policy review.
- Local development uses HTTP and `DEBUG=1`. Before deployment, set a strong `DJANGO_SECRET_KEY`, `DJANGO_DEBUG=0`, configure `DJANGO_ALLOWED_HOSTS`, use HTTPS, configure secure cookies/proxy settings, back up the database, and review permissions, retention, rate limiting, logging, and upload handling.
- AI output can be wrong. Do not automatically execute commands or treat an AI summary as proof of an incident.

## Basic workflow
1. Create an incident from **New incident**.
2. Visit **AI Assistant** to ask about a sanitized error or event.
3. Visit **Log Analyzer** and upload a small `.log`, `.txt`, or `.csv` authentication log.
4. Review the calculated counts and AI explanation, then document verified findings in the incident queue.

## Project structure

```text
secure_ai_assistant/
├── manage.py
├── config/                  # Django project settings and URLs
├── assistant/               # Incident models, views, forms and AI service
│   ├── templates/assistant/  # HTML pages
│   └── static/assistant/     # CSS styles
├── requirements.txt
├── .env.example
└── README.md
```
