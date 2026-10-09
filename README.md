# Education Portal (Flask)

## Initial admin login
- User ID: `admin`
- Initial password: `ChangeMe@123`
- First login requires changing the default password.

## Run on Windows
1. Install Python 3.11 or 3.12 and check **Add Python to PATH**.
2. Open Command Prompt in this folder and run:
   ```bat
   py -m venv .venv
   .venv\Scripts\activate
   python -m pip install -r requirements.txt
   python -m flask --app app run
   ```
3. Open http://127.0.0.1:5000

## Render
Set runtime to Python 3, root directory blank if `app.py` is at repository root.
Build command: `pip install -r requirements.txt`
Start command: `gunicorn --bind 0.0.0.0:$PORT app:app`

Set environment variables in Render:
- `SECRET_KEY`: long random secret
- `INITIAL_ADMIN_PASSWORD`: only used when database is first created
- `ADMIN_RECOVERY_CODE`: private code for admin password reset
- `GOOGLE_DRIVE_ROOT_FOLDER_ID`: ID of a folder in your Drive
- `GOOGLE_SERVICE_ACCOUNT_JSON`: full JSON key contents for service account

## Google Drive
Enable Google Drive API in Google Cloud, create a service account and JSON key, then share the root folder in your personal Drive with the service account's email as Editor. Put the root folder ID and full JSON key in Render Environment. Never upload credentials to GitHub. Class folders and uploaded files are created inside that shared folder.

## Important
- SQLite and local uploaded files can disappear on Render if the service uses an ephemeral filesystem. Use a persistent disk (for example set `DATABASE_PATH=/var/data/portal.db` on a disk mounted at `/var/data`) or a managed PostgreSQL database for production.
- The Forgot Admin Password form uses `ADMIN_RECOVERY_CODE`; if it is not configured, password reset is disabled.
- Students can only access files listed for their assigned class through the app. Google Drive “View” redirects to Drive's link; configure Drive permissions accordingly.
- Passwords are stored as hashes, not plaintext. Do not commit `.env`, service account JSON, database files, or credentials.
- This is a starter app. Before a public launch, add backups, rate limiting, email-based recovery, persistent storage, and production security review.
