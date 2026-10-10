import os, io, json, sqlite3, secrets
from pathlib import Path
from datetime import datetime
from functools import wraps
from flask import Flask, request, session, redirect, url_for, flash, render_template_string, send_file, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix

try:
    from google.oauth2 import service_account, credentials as oauth_credentials
    from google.auth.transport.requests import Request as GoogleAuthRequest
    from google_auth_oauthlib.flow import Flow
    from googleapiclient.discovery import build
    from googleapiclient.http import MediaIoBaseUpload, MediaIoBaseDownload
except ImportError:
    service_account = oauth_credentials = GoogleAuthRequest = Flow = None
    build = MediaIoBaseUpload = MediaIoBaseDownload = None

ROOT = Path(__file__).resolve().parent
DB_PATH = os.environ.get("DATABASE_PATH", str(ROOT / "portal.db"))
Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
_backup_suspended = True
UPLOAD_DIR = Path(os.environ.get("LOCAL_UPLOAD_DIR", ROOT / "local_uploads"))
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
DRIVE_ROOT = os.environ.get("GOOGLE_DRIVE_ROOT_FOLDER_ID", "").strip()
GOOGLE_SCOPES = ["https://www.googleapis.com/auth/drive"]
OAUTH_CLIENT_FILE = Path(os.environ.get("GOOGLE_OAUTH_CLIENT_FILE", str(ROOT / "credentials" / "client_secret.json")))
OAUTH_TOKEN_FILE = Path(os.environ.get("GOOGLE_OAUTH_TOKEN_FILE", str(ROOT / "credentials" / "token.json")))
ALLOWED = {".pdf", ".doc", ".docx", ".odt", ".rtf", ".txt", ".png", ".jpg", ".jpeg", ".gif", ".webp"}

app = Flask(__name__)
# Render terminates HTTPS at its proxy; trust its forwarded scheme/host for OAuth callback URLs.
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-this-" + secrets.token_hex(16))
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE", "0") == "1"

class BackupConnection(sqlite3.Connection):
    """Commit normal transactions, then best-effort backup changed DBs to Drive."""
    def __exit__(self, exc_type, exc, tb):
        changed = self.total_changes > 0
        try:
            result = super().__exit__(exc_type, exc, tb)
        finally:
            self.close()
        if exc_type is None and changed and not _backup_suspended:
            try:
                backup_database_to_drive()
            except Exception:
                app.logger.exception("Google Drive database backup failed")
        return result


def db():
    c = sqlite3.connect(DB_PATH, factory=BackupConnection)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    return c

def now():
    return datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")

def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS admins(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT NOT NULL, must_change INTEGER DEFAULT 1);
        CREATE TABLE IF NOT EXISTS classes(id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, drive_id TEXT, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS students(id INTEGER PRIMARY KEY, name TEXT NOT NULL, class_id INTEGER NOT NULL, email TEXT NOT NULL, address TEXT NOT NULL, mobile TEXT NOT NULL, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, drive_id TEXT, created_at TEXT NOT NULL, active INTEGER DEFAULT 1, FOREIGN KEY(class_id) REFERENCES classes(id));
        CREATE TABLE IF NOT EXISTS documents(id INTEGER PRIMARY KEY, title TEXT NOT NULL, filename TEXT NOT NULL, ext TEXT NOT NULL, class_id INTEGER NOT NULL, drive_id TEXT, web_link TEXT, local_path TEXT, created_at TEXT NOT NULL, FOREIGN KEY(class_id) REFERENCES classes(id));
        CREATE TABLE IF NOT EXISTS activity(id INTEGER PRIMARY KEY, student_id INTEGER, username TEXT NOT NULL, action TEXT NOT NULL, details TEXT NOT NULL, at TEXT NOT NULL, FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE SET NULL);
        CREATE TABLE IF NOT EXISTS deleted_students(id INTEGER PRIMARY KEY, name TEXT, username TEXT, class_name TEXT, deleted_at TEXT, deleted_by TEXT);
        CREATE TABLE IF NOT EXISTS app_settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        """)
        if not c.execute("SELECT id FROM admins WHERE username='admin'").fetchone():
            c.execute("INSERT INTO admins(username,password_hash,must_change) VALUES(?,?,1)",
                      ("admin", generate_password_hash(os.environ.get("INITIAL_ADMIN_PASSWORD", "ChangeMe@123"))))

def oauth_redirect_uri():
    # Set GOOGLE_OAUTH_REDIRECT_URI explicitly on Render if needed.
    return os.environ.get("GOOGLE_OAUTH_REDIRECT_URI", "").strip() or url_for("google_oauth_callback", _external=True)


def oauth_flow(state=None):
    if not Flow or not OAUTH_CLIENT_FILE.exists():
        return None
    # OAuthlib permits HTTP only for local development. Render must use HTTPS.
    if request.host.split(":")[0] in ("127.0.0.1", "localhost"):
        os.environ.setdefault("OAUTHLIB_INSECURE_TRANSPORT", "1")
    return Flow.from_client_secrets_file(
        str(OAUTH_CLIENT_FILE),
        scopes=GOOGLE_SCOPES,
        state=state,
        redirect_uri=oauth_redirect_uri(),
    )


def read_oauth_credentials():
    if not oauth_credentials:
        return None
    env_token = os.environ.get("GOOGLE_OAUTH_TOKEN_JSON", "").strip()
    try:
        if env_token:
            creds = oauth_credentials.Credentials.from_authorized_user_info(
                json.loads(env_token), scopes=GOOGLE_SCOPES
            )
            token_path = None
        elif OAUTH_TOKEN_FILE.exists():
            creds = oauth_credentials.Credentials.from_authorized_user_file(
                str(OAUTH_TOKEN_FILE), scopes=GOOGLE_SCOPES
            )
            token_path = OAUTH_TOKEN_FILE
        else:
            return None
        if creds.expired and creds.refresh_token:
            creds.refresh(GoogleAuthRequest())
            if token_path:
                token_path.parent.mkdir(parents=True, exist_ok=True)
                token_path.write_text(creds.to_json(), encoding="utf-8")
        if creds.valid:
            return creds
    except Exception:
        app.logger.exception("Google OAuth credentials could not be loaded/refreshed")
    return None


def drive():
    if not build:
        return None
    # Preferred path: OAuth on behalf of the owner's personal Google account.
    creds = read_oauth_credentials()
    if creds:
        return build("drive", "v3", credentials=creds, cache_discovery=False)

    # Optional legacy service-account fallback for an existing setup.
    if not DRIVE_ROOT or not service_account:
        return None
    raw = os.environ.get("GOOGLE_SERVICE_ACCOUNT_JSON", "").strip()
    try:
        if raw:
            creds = service_account.Credentials.from_service_account_info(
                json.loads(raw), scopes=GOOGLE_SCOPES
            )
        else:
            p = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "")
            if not p or not Path(p).exists():
                return None
            creds = service_account.Credentials.from_service_account_file(
                p, scopes=GOOGLE_SCOPES
            )
        return build("drive", "v3", credentials=creds, cache_discovery=False)
    except Exception:
        app.logger.exception("Google service-account credentials could not be loaded")
        return None


def drive_root_id(service=None):
    if DRIVE_ROOT:
        return DRIVE_ROOT
    with db() as c:
        row = c.execute("SELECT value FROM app_settings WHERE key='google_drive_root_id'").fetchone()
    if row:
        return row["value"]
    service = service or drive()
    if not service:
        return None
    folder = service.files().create(
        body={"name": "Education Portal", "mimeType": "application/vnd.google-apps.folder"},
        fields="id"
    ).execute()
    root_id = folder["id"]
    with db() as c:
        c.execute("INSERT OR REPLACE INTO app_settings(key,value) VALUES('google_drive_root_id',?)", (root_id,))
    return root_id


def make_folder(name, parent=None):
    s = drive()
    if not s:
        return None
    parent_id = parent or drive_root_id(s)
    if not parent_id:
        return None
    r = s.files().create(
        body={"name": name, "mimeType": "application/vnd.google-apps.folder", "parents": [parent_id]},
        fields="id"
    ).execute()
    return r["id"]


def drive_upload(file, parent, filename):
    s = drive()
    raw = file.read()
    file.stream.seek(0)
    media = MediaIoBaseUpload(io.BytesIO(raw), mimetype=file.mimetype or "application/octet-stream", resumable=True)
    r = s.files().create(body={"name": filename, "parents": [parent]}, media_body=media,
                         fields="id,webViewLink").execute()
    return r["id"], r.get("webViewLink")

def drive_download(fid):
    s = drive()
    meta = s.files().get(fileId=fid, fields="name,mimeType").execute()
    stream = io.BytesIO()
    req = s.files().get_media(fileId=fid)
    downloader = MediaIoBaseDownload(stream, req)
    done = False
    while not done: _, done = downloader.next_chunk()
    stream.seek(0)
    return stream, meta.get("name", "download"), meta.get("mimeType", "application/octet-stream")


# Google Drive backup is stored in the authorized user's Drive root, independently
# of app_settings, so it can still be found after the local SQLite DB disappears.
DRIVE_DB_BACKUP_NAME = os.environ.get("DRIVE_DB_BACKUP_NAME", "study-portal-database-backup.sqlite3")

def _find_drive_db_backup(service):
    result = service.files().list(
        q="name='" + DRIVE_DB_BACKUP_NAME.replace("'", "\\'") + "' and trashed=false",
        orderBy="modifiedTime desc", pageSize=1,
        fields="files(id,name,modifiedTime,size)"
    ).execute()
    files = result.get("files", [])
    return files[0] if files else None


def backup_database_to_drive():
    """Upload/replace the full SQLite DB in Drive. Failure never breaks a user action."""
    service = drive()
    if not service or not Path(DB_PATH).exists() or Path(DB_PATH).stat().st_size == 0:
        return False
    # A closed SQLite connection is used by callers before this runs. Read bytes
    # only after transaction commit so the backup represents committed data.
    payload = Path(DB_PATH).read_bytes()
    media = MediaIoBaseUpload(io.BytesIO(payload), mimetype="application/vnd.sqlite3", resumable=True)
    existing = _find_drive_db_backup(service)
    if existing:
        service.files().update(fileId=existing["id"], media_body=media, fields="id,name,modifiedTime").execute()
    else:
        service.files().create(body={"name": DRIVE_DB_BACKUP_NAME}, media_body=media,
                               fields="id,name,modifiedTime").execute()
    app.logger.info("SQLite database backup saved to Google Drive (%s)", DRIVE_DB_BACKUP_NAME)
    return True


def restore_database_from_drive(force=False):
    """Restore on fresh startup, or on admin request only if the current DB has no user data."""
    db_file = Path(DB_PATH)
    if db_file.exists() and db_file.stat().st_size > 0:
        if not force:
            return False
        # Never replace a database that already has class/student/document records.
        try:
            current = sqlite3.connect(str(db_file))
            tables = {r[0] for r in current.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            required = {"students", "classes", "documents"}
            if not required.issubset(tables):
                return False
            counts = [current.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                      for table in ("students", "classes", "documents")]
            if any(counts):
                return False
        except sqlite3.Error:
            return False
        finally:
            try: current.close()
            except Exception: pass
    service = drive()
    if not service:
        app.logger.warning("Drive restore skipped: Google Drive credentials are unavailable")
        return False
    backup = _find_drive_db_backup(service)
    if not backup:
        app.logger.info("No database backup found in Google Drive yet")
        return False
    stream = io.BytesIO()
    downloader = MediaIoBaseDownload(stream, service.files().get_media(fileId=backup["id"]))
    done = False
    while not done:
        _, done = downloader.next_chunk()
    stream.seek(0)
    import tempfile
    fd, temp_name = tempfile.mkstemp(prefix="portal-restore-", suffix=".sqlite3", dir=str(db_file.parent))
    os.close(fd)
    try:
        Path(temp_name).write_bytes(stream.read())
        check = sqlite3.connect(temp_name)
        try:
            integrity = check.execute("PRAGMA integrity_check").fetchone()[0]
            tables = {r[0] for r in check.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if integrity != "ok" or not {"admins", "students", "classes"}.issubset(tables):
                raise RuntimeError("Drive backup is not a valid Study Portal database")
        finally:
            check.close()
        os.replace(temp_name, db_file)
        app.logger.info("Restored portal database from Google Drive backup %s", backup["id"])
        return True
    finally:
        try:
            if os.path.exists(temp_name): os.remove(temp_name)
        except OSError:
            pass

def log(username, action, details, student_id=None):
    with db() as c:
        c.execute("INSERT INTO activity(student_id,username,action,details,at) VALUES(?,?,?,?,?)",
                  (student_id, username, action, details[:500], now()))

def student():
    sid = session.get("student_id")
    if not sid: return None
    with db() as c:
        return c.execute("""SELECT s.*,cl.name class_name FROM students s JOIN classes cl ON cl.id=s.class_id
                            WHERE s.id=? AND s.active=1""", (sid,)).fetchone()

def need_admin(fn):
    @wraps(fn)
    def w(*a, **kw):
        if session.get("role") != "admin":
            flash("Admin login required.", "error"); return redirect(url_for("login"))
        return fn(*a, **kw)
    return w

def need_student(fn):
    @wraps(fn)
    def w(*a, **kw):
        if session.get("role") != "student" or not student():
            flash("Student login required.", "error"); return redirect(url_for("login"))
        return fn(*a, **kw)
    return w

SHELL = """<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>
<title>{{ title or 'Study Portal' }}</title><style>
*{box-sizing:border-box}body{margin:0;background:#f2f5fa;color:#172033;font:16px Arial,sans-serif;line-height:1.45}
header{background:#152842;color:white;padding:16px max(18px,calc((100% - 1150px)/2));display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}
header a{color:#e0ecff;text-decoration:none;margin-right:14px}.brand{font-size:20px;font-weight:bold;color:white}
main{max-width:1150px;margin:26px auto;padding:0 16px}.card{background:white;border:1px solid #dce3ee;border-radius:14px;padding:20px;margin:0 0 18px;min-width:0}
.auth{max-width:520px;margin:35px auto}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}
h1{font-size:28px;margin-top:0}h2{font-size:20px;margin-top:0}label{display:block;font-weight:bold;margin:10px 0 5px}
input,select,textarea{width:100%;padding:10px;border:1px solid #c5cfdd;border-radius:8px;font:inherit;background:white}
button,.btn{display:inline-block;border:0;border-radius:8px;background:#2563eb;color:white;padding:10px 14px;font-weight:bold;text-decoration:none;cursor:pointer;margin-top:10px}
.danger{background:#b91c1c}.muted{color:#64748b}.msg{padding:11px;border-radius:8px;margin:8px 0;background:#dbeafe}.success{background:#dcfce7}.error{background:#fee2e2}.warning{background:#fef3c7}
table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;padding:9px;border-bottom:1px solid #e2e8f0;vertical-align:top}th{background:#f8fafc} .scroll{overflow:auto}
small{color:#64748b}.actions{display:flex;gap:6px;flex-wrap:wrap}.pill{background:#e0f2fe;border-radius:20px;padding:5px 10px}
@media(max-width:760px){.grid{grid-template-columns:1fr}main{margin:16px auto}.card{padding:15px}header{display:block}header nav{margin-top:8px}}
</style></head><body><header><a class=brand href="{{ url_for('index') }}">Study Portal</a><nav>
{% if session.get('role')=='admin' %}<a href="{{ url_for('admin') }}">Dashboard</a><a href="{{ url_for('change_password') }}">Change password</a>{% elif session.get('role')=='student' %}<a href="{{ url_for('student_home') }}">My class</a><a href="{{ url_for('change_password') }}">Change password</a>{% endif %}
{% if session.get('role') %}<a href="{{ url_for('logout') }}">Logout</a>{% else %}<a href="{{ url_for('login') }}">Login</a><a href="{{ url_for('register') }}">Register</a>{% endif %}
</nav></header><main>{% for cat,msg in get_flashed_messages(with_categories=true) %}<div class="msg {{ cat }}">{{ msg }}</div>{% endfor %}{{ body|safe }}</main></body></html>"""

def page(body, title="Study Portal", **ctx):
    return render_template_string(SHELL, body=render_template_string(body, **ctx), title=title)

@app.after_request
def headers(r):
    r.headers["X-Content-Type-Options"]="nosniff"; r.headers["X-Frame-Options"]="SAMEORIGIN"
    r.headers["Referrer-Policy"]="strict-origin-when-cross-origin"
    return r

@app.route("/")
def index():
    if session.get("role")=="admin": return redirect(url_for("admin"))
    if session.get("role")=="student": return redirect(url_for("student_home"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        role=request.form.get("role","student"); u=request.form.get("username","").strip(); p=request.form.get("password","")
        with db() as c:
            if role=="admin": row=c.execute("SELECT * FROM admins WHERE username=?",(u,)).fetchone()
            else: row=c.execute("SELECT * FROM students WHERE username=? AND active=1",(u,)).fetchone()
        if row and check_password_hash(row["password_hash"],p):
            session.clear()
            if role=="admin":
                session.update(role="admin",admin_id=row["id"],username=row["username"])
                if row["must_change"]: flash("First login: change the default admin password now.","warning"); return redirect(url_for("change_password"))
                return redirect(url_for("admin"))
            session.update(role="student",student_id=row["id"],username=row["username"])
            log(u,"LOGIN","Student logged in",row["id"]); return redirect(url_for("student_home"))
        flash("Invalid user ID or password.","error")
    return page("""<section class=card class=auth style='max-width:500px;margin:35px auto'><h1>Login</h1><form method=post>
    <label>Login type</label><select name=role><option value=student>Student login</option><option value=admin>Admin login</option></select>
    <label>User ID</label><input name=username required autocomplete=username><label>Password</label><input type=password name=password required autocomplete=current-password>
    <button>Login</button></form><p><a href="{{ url_for('register') }}">Student registration</a> · <a href="{{ url_for('forgot') }}">Forgot admin password?</a></p>
    <small>Initial admin: ID <b>admin</b>, password <b>ChangeMe@123</b>. Change it immediately.</small></section>""","Login")

@app.route("/register",methods=["GET","POST"])
def register():
    with db() as c: classes=c.execute("SELECT * FROM classes ORDER BY name").fetchall()
    if request.method=="POST":
        name=request.form.get("name","").strip(); class_id=request.form.get("class_id",""); email=request.form.get("email","").strip()
        address=request.form.get("address","").strip(); mobile=request.form.get("mobile","").strip()
        u=request.form.get("username","").strip(); p=request.form.get("password","")
        if not all([name,class_id,email,address,mobile,u,p]): flash("Fill all fields.","error")
        elif len(p)<8: flash("Student password must be at least 8 characters.","error")
        else:
            try:
                with db() as c:
                    cl=c.execute("SELECT * FROM classes WHERE id=?",(class_id,)).fetchone()
                    if not cl: flash("Select a valid class.","error"); return redirect(url_for("register"))
                    sid_folder=make_folder("studentdata-"+u) if drive() else None
                    c.execute("""INSERT INTO students(name,class_id,email,address,mobile,username,password_hash,drive_id,created_at)
                    VALUES(?,?,?,?,?,?,?,?,?)""",(name,int(class_id),email,address,mobile,u,generate_password_hash(p),sid_folder,now()))
                flash("Registration successful. Please log in.","success"); return redirect(url_for("login"))
            except sqlite3.IntegrityError: flash("That user ID is already taken.","error")
            except Exception: app.logger.exception("Registration error"); flash("Registration failed. Check server logs/Drive setup.","error")
    return page("""<section class=card style='max-width:620px;margin:auto'><h1>Student registration</h1>
    {% if not classes %}<div class='msg warning'>Admin must create a class before students can register.</div>{% endif %}
    <form method=post><label>Student name</label><input name=name required><label>Class</label><select name=class_id required><option value=''>Select class</option>{% for c in classes %}<option value={{ c.id }}>{{ c.name }}</option>{% endfor %}</select>
    <label>Email</label><input type=email name=email required><label>Address</label><textarea name=address required></textarea><label>Mobile number</label><input name=mobile required>
    <label>Create user ID</label><input name=username minlength=3 required><label>Create password (8+ characters)</label><input type=password name=password minlength=8 required>
    <button {% if not classes %}disabled{% endif %}>Save registration</button></form></section>""","Student registration",classes=classes)

@app.route("/forgot",methods=["GET","POST"])
def forgot():
    code=os.environ.get("ADMIN_RECOVERY_CODE","")
    if request.method=="POST":
        u=request.form.get("username","").strip(); provided=request.form.get("recovery_code","")
        p=request.form.get("new_password",""); confirm=request.form.get("confirm_password","")
        if not code: flash("Set ADMIN_RECOVERY_CODE in the hosting environment first.","error")
        elif not secrets.compare_digest(provided,code): flash("Recovery code is incorrect.","error")
        elif len(p)<12: flash("Admin password must be at least 12 characters.","error")
        elif p!=confirm: flash("Passwords do not match.","error")
        else:
            with db() as c: cur=c.execute("UPDATE admins SET password_hash=?,must_change=0 WHERE username=?",(generate_password_hash(p),u))
            if cur.rowcount: flash("Password reset. Please log in.","success"); return redirect(url_for("login"))
            flash("Admin account not found.","error")
    return page("""<section class=card style='max-width:550px;margin:auto'><h1>Forgot admin password</h1>
    <p class=muted>Requires the private recovery code configured by the site owner.</p><form method=post>
    <label>Admin ID</label><input name=username value=admin required><label>Recovery code</label><input type=password name=recovery_code required>
    <label>New password (12+ characters)</label><input type=password name=new_password minlength=12 required><label>Confirm password</label><input type=password name=confirm_password minlength=12 required><button>Reset password</button></form></section>""","Password recovery")

@app.route("/logout")
def logout():
    if session.get("role")=="student": log(session.get("username","student"),"LOGOUT","Student logged out",session.get("student_id"))
    session.clear(); flash("Logged out.","success"); return redirect(url_for("login"))

@app.route("/admin")
@need_admin
def admin():
    with db() as c:
        students=c.execute("""SELECT s.*,cl.name class_name FROM students s JOIN classes cl ON cl.id=s.class_id WHERE s.active=1 ORDER BY s.id DESC""").fetchall()
        classes=c.execute("SELECT * FROM classes ORDER BY name").fetchall()
        docs=c.execute("""SELECT d.*,cl.name class_name FROM documents d JOIN classes cl ON cl.id=d.class_id ORDER BY d.id DESC LIMIT 100""").fetchall()
        activities=c.execute("SELECT * FROM activity ORDER BY id DESC LIMIT 100").fetchall()
        deleted=c.execute("SELECT * FROM deleted_students ORDER BY id DESC LIMIT 100").fetchall()
    body="""<h1>Admin dashboard</h1><p class=muted>Manage folders, student accounts, learning files and history.</p>
    <section class=card><h2>Google Drive connection</h2>
    <p>{{ 'Connected to Google Drive' if drive_ready else 'Not connected — files will be saved locally until you connect Drive.' }}</p>
    {% if drive_ready %}<p class=success>Google Drive is ready.</p><form method=post action="{{ url_for('restore_drive_backup') }}" onsubmit="return confirm('Restore the saved database from Google Drive? This works only if this website currently has no students/classes/documents.');"><button>Restore database backup from Google Drive</button></form><small>Restore is blocked automatically if this database already contains students, classes or uploaded-file records.</small>{% else %}
    <p><a class=btn href="{{ url_for('google_drive_connect') }}">Connect my Google Drive</a></p>
    <small>Use the Google account where you want portal files stored. OAuth client JSON must be in credentials/client_secret.json.</small>{% endif %}</section>
    <div class=grid><section class=card><h2>Create class / folder</h2><form method=post action="{{ url_for('create_class') }}"><label>Class/folder name</label><input name=name placeholder='Class 10' required><button>Create folder</button></form>
    <h3>Existing folders</h3>{% for c in classes %}<p>📁 {{ c.name }} <small>{{ 'Google Drive' if c.drive_id else 'Local / Drive not configured' }}</small></p>{% else %}<p>No folders yet.</p>{% endfor %}</section>
    <section class=card><h2>Insert data</h2><form method=post action="{{ url_for('upload') }}" enctype=multipart/form-data><label>Select folder</label><select name=class_id required><option value=''>Select class</option>{% for c in classes %}<option value={{ c.id }}>{{ c.name }}</option>{% endfor %}</select><label>Select Word, PDF, images or TXT (multiple allowed)</label><input type=file name=files multiple required accept='.pdf,.doc,.docx,.odt,.rtf,.txt,.png,.jpg,.jpeg,.gif,.webp'><button {% if not classes %}disabled{% endif %}>Send data</button></form><p><small>Max 50 MB per request. Drive status: {{ 'connected' if drive_ready else 'not configured' }}.</small></p></section></div>
    <section class=card><h2>Student list</h2><div class=scroll><table><tr><th>Name</th><th>Class</th><th>Email</th><th>Address</th><th>Mobile</th><th>User ID</th><th>Registered</th><th>Action</th></tr>
    {% for s in students %}<tr><td>{{ s.name }}</td><td>{{ s.class_name }}</td><td>{{ s.email }}</td><td>{{ s.address }}</td><td>{{ s.mobile }}</td><td>{{ s.username }}</td><td>{{ s.created_at }}</td><td><form method=post action="{{ url_for('delete_student',sid=s.id) }}" onsubmit="return confirm('Disable this student?')"><button class=danger>Delete</button></form></td></tr>{% else %}<tr><td colspan=8>No students registered.</td></tr>{% endfor %}</table></div></section>
    <section class=card><h2>Uploaded data</h2><div class=scroll><table><tr><th>Title</th><th>Filename</th><th>Class</th><th>Uploaded</th><th>Storage</th></tr>{% for d in docs %}<tr><td>{{ d.title }}</td><td>{{ d.filename }}</td><td>{{ d.class_name }}</td><td>{{ d.created_at }}</td><td>{{ 'Google Drive' if d.drive_id else 'Local' }}</td></tr>{% else %}<tr><td colspan=5>No uploaded files.</td></tr>{% endfor %}</table></div></section>
    <section class=card><h2>Student login / read / download history</h2><div class=scroll><table><tr><th>Date/time</th><th>User ID</th><th>Action</th><th>Details</th></tr>{% for a in activities %}<tr><td>{{ a.at }}</td><td>{{ a.username }}</td><td>{{ a.action }}</td><td>{{ a.details }}</td></tr>{% else %}<tr><td colspan=4>No activity yet.</td></tr>{% endfor %}</table></div></section>
    <section class=card><h2>Deleted student history</h2><div class=scroll><table><tr><th>Name</th><th>User ID</th><th>Class</th><th>Deleted at</th><th>Deleted by</th></tr>{% for d in deleted %}<tr><td>{{ d.name }}</td><td>{{ d.username }}</td><td>{{ d.class_name }}</td><td>{{ d.deleted_at }}</td><td>{{ d.deleted_by }}</td></tr>{% else %}<tr><td colspan=5>No deleted accounts.</td></tr>{% endfor %}</table></div></section>"""
    return page(body,"Admin dashboard",students=students,classes=classes,docs=docs,activities=activities,deleted=deleted,drive_ready=bool(drive()))

@app.route("/admin/google-drive/connect")
@need_admin
def google_drive_connect():
    if not Flow:
        flash("Google OAuth packages are missing. Run: pip install -r requirements.txt", "error")
        return redirect(url_for("admin"))
    if not OAUTH_CLIENT_FILE.exists():
        flash("OAuth client JSON not found. Put it at credentials/client_secret.json or set GOOGLE_OAUTH_CLIENT_FILE.", "error")
        return redirect(url_for("admin"))
    try:
        flow = oauth_flow()
        if not flow:
            flash("Google OAuth is not available. Check your OAuth client JSON and dependencies.", "error")
            return redirect(url_for("admin"))

        # Explicitly create and persist the PKCE verifier across the redirect.
        # A new Flow object is created in the callback, so it must be restored there.
        code_verifier = secrets.token_urlsafe(64)
        flow.code_verifier = code_verifier
        authorization_url, state = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true",
            prompt="consent",
        )
        session["google_oauth_state"] = state
        session["google_oauth_code_verifier"] = code_verifier
        session.modified = True
        return redirect(authorization_url)
    except Exception:
        app.logger.exception("Could not start Google OAuth")
        flash("Could not start Google Drive connection. Check server logs.", "error")
        return redirect(url_for("admin"))


@app.route("/google/oauth/callback")
def google_oauth_callback():
    if session.get("role") != "admin":
        flash("Log in as admin before connecting Google Drive.", "error")
        return redirect(url_for("login"))
    expected_state = session.pop("google_oauth_state", None)
    received_state = request.args.get("state")
    if not expected_state or not received_state or not secrets.compare_digest(expected_state, received_state):
        flash("Google OAuth state did not match. Please try connecting again.", "error")
        return redirect(url_for("admin"))
    try:
        code_verifier = session.pop("google_oauth_code_verifier", None)
        if not code_verifier:
            flash("Google OAuth session expired. Please click Connect my Google Drive and try again.", "error")
            return redirect(url_for("admin"))

        flow = oauth_flow(state=expected_state)
        if not flow:
            flash("OAuth client JSON or required packages are missing.", "error")
            return redirect(url_for("admin"))
        # Restore the same PKCE verifier used to create the authorization request.
        flow.code_verifier = code_verifier
        flow.fetch_token(authorization_response=request.url)
        creds = flow.credentials
        OAUTH_TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
        OAUTH_TOKEN_FILE.write_text(creds.to_json(), encoding="utf-8")
        # Verify that the authorized account can reach Drive before reporting success.
        service = build("drive", "v3", credentials=creds, cache_discovery=False)
        service.about().get(fields="user(emailAddress)").execute()
        flash("Google Drive connected! New uploads will be stored in your Google Drive.", "success")
    except Exception:
        app.logger.exception("Google OAuth callback failed")
        flash("Google Drive connection failed. Check redirect URI, test-user access, and server logs.", "error")
    return redirect(url_for("admin"))


@app.route("/admin/class",methods=["POST"])
@need_admin
def create_class():
    name=request.form.get("name","").strip()
    if not name: flash("Folder name is required.","error"); return redirect(url_for("admin"))
    try:
        folder=make_folder(name) if drive() else None
        with db() as c: c.execute("INSERT INTO classes(name,drive_id,created_at) VALUES(?,?,?)",(name,folder,now()))
        flash("Class/folder created"+(" in Google Drive." if folder else " in portal (Drive not configured)."),"success")
    except sqlite3.IntegrityError: flash("Class name already exists.","error")
    except Exception: app.logger.exception("Class create failed"); flash("Folder creation failed; check Drive setup and logs.","error")
    return redirect(url_for("admin"))

@app.route("/admin/upload",methods=["POST"])
@need_admin
def upload():
    class_id=request.form.get("class_id",""); items=request.files.getlist("files")
    with db() as c: cl=c.execute("SELECT * FROM classes WHERE id=?",(class_id,)).fetchone()
    if not cl: flash("Select a valid folder.","error"); return redirect(url_for("admin"))
    count=0
    for f in items:
        if not f or not f.filename: continue
        name=secure_filename(f.filename); ext=Path(name).suffix.lower()
        if ext not in ALLOWED: flash("Skipped unsupported file: "+name,"warning"); continue
        try:
            fid=link=local=None
            if drive() and cl["drive_id"]: fid,link=drive_upload(f,cl["drive_id"],name)
            else:
                folder=UPLOAD_DIR/str(class_id); folder.mkdir(parents=True,exist_ok=True)
                local=str(folder/(secrets.token_hex(8)+"_"+name)); f.save(local)
            with db() as c: c.execute("INSERT INTO documents(title,filename,ext,class_id,drive_id,web_link,local_path,created_at) VALUES(?,?,?,?,?,?,?,?)",
                                     (Path(name).stem,name,ext,int(class_id),fid,link,local,now()))
            count+=1
        except Exception: app.logger.exception("File upload failed"); flash("Upload failed for "+name+". Check logs/Drive permissions.","error")
    if count: flash(f"Uploaded {count} file(s).","success")
    return redirect(url_for("admin"))

@app.route("/admin/delete/<int:sid>",methods=["POST"])
@need_admin
def delete_student(sid):
    with db() as c:
        s=c.execute("SELECT s.*,cl.name class_name FROM students s JOIN classes cl ON cl.id=s.class_id WHERE s.id=?",(sid,)).fetchone()
        if s:
            c.execute("INSERT INTO deleted_students(name,username,class_name,deleted_at,deleted_by) VALUES(?,?,?,?,?)",(s["name"],s["username"],s["class_name"],now(),session["username"]))
            c.execute("UPDATE students SET active=0 WHERE id=?",(sid,))
            c.execute("INSERT INTO activity(student_id,username,action,details,at) VALUES(?,?,?,?,?)",(sid,s["username"],"STUDENT_DELETED","Account disabled by admin",now()))
            flash("Student disabled and recorded in history.","success")
        else: flash("Student not found.","error")
    return redirect(url_for("admin"))

@app.route("/admin/restore-drive-backup", methods=["POST"])
@need_admin
def restore_drive_backup():
    try:
        restored = restore_database_from_drive(force=True)
        if restored:
            flash("Database restored from Google Drive. Please log in again if needed.", "success")
            session.clear()
            return redirect(url_for("login"))
        flash("Restore was not done: no Drive backup was found, Drive access is unavailable, or this database already contains records. Existing data was not overwritten.", "warning")
    except Exception:
        app.logger.exception("Manual Google Drive database restore failed")
        flash("Restore failed. Existing database was not intentionally overwritten; check server logs.", "error")
    return redirect(url_for("admin"))


@app.route("/change-password",methods=["GET","POST"])
def change_password():
    role=session.get("role")
    if role not in ("admin","student"): return redirect(url_for("login"))
    if request.method=="POST":
        current=request.form.get("current_password",""); new=request.form.get("new_password",""); confirm=request.form.get("confirm_password","")
        is_admin=role=="admin"; table="admins" if is_admin else "students"; ident=session["admin_id"] if is_admin else session["student_id"]
        with db() as c: row=c.execute(f"SELECT * FROM {table} WHERE id=?",(ident,)).fetchone()
        minlen=12 if is_admin else 8
        if not row or not check_password_hash(row["password_hash"],current): flash("Current password is incorrect.","error")
        elif len(new)<minlen: flash(f"Password must be at least {minlen} characters.","error")
        elif new!=confirm: flash("Passwords do not match.","error")
        else:
            with db() as c:
                if is_admin: c.execute("UPDATE admins SET password_hash=?,must_change=0 WHERE id=?",(generate_password_hash(new),ident))
                else: c.execute("UPDATE students SET password_hash=? WHERE id=?",(generate_password_hash(new),ident))
            if not is_admin: log(session["username"],"PASSWORD_CHANGED","Student changed password",ident)
            flash("Password updated.","success"); return redirect(url_for("admin" if is_admin else "student_home"))
    return page("""<section class=card style='max-width:520px;margin:auto'><h1>Change password</h1><form method=post>
    <label>Current password</label><input type=password name=current_password required><label>New password ({{ 12 if session.get('role')=='admin' else 8 }}+ characters)</label><input type=password name=new_password minlength={{ 12 if session.get('role')=='admin' else 8 }} required>
    <label>Confirm new password</label><input type=password name=confirm_password required><button>Update password</button></form></section>""","Change password")

@app.route("/student")
@need_student
def student_home():
    s=student()
    with db() as c:
        docs=c.execute("SELECT * FROM documents WHERE class_id=? ORDER BY id DESC",(s["class_id"],)).fetchall()
        history=c.execute("SELECT * FROM activity WHERE student_id=? ORDER BY id DESC LIMIT 100",(s["id"],)).fetchall()
    body="""<h1>Hello, {{ s.name }}</h1><p class=muted>Your class: <b>{{ s.class_name }}</b>. Only your class's files appear here.</p>
    <section class=card><h2>Your class data</h2><div class=scroll><table><tr><th>Title</th><th>File</th><th>Uploaded</th><th>Actions</th></tr>
    {% for d in docs %}<tr><td>{{ d.title }}</td><td>{{ d.filename }}</td><td>{{ d.created_at }}</td><td class=actions><a class=btn href="{{ url_for('view_doc',did=d.id) }}">View</a><a class=btn href="{{ url_for('download_doc',did=d.id) }}">Download</a></td></tr>{% else %}<tr><td colspan=4>No class data uploaded yet.</td></tr>{% endfor %}</table></div></section>
    <section class=card><h2>Your history</h2><div class=scroll><table><tr><th>Date/time</th><th>Action</th><th>Details</th></tr>{% for a in history %}<tr><td>{{ a.at }}</td><td>{{ a.action }}</td><td>{{ a.details }}</td></tr>{% else %}<tr><td colspan=3>Your activity will appear here.</td></tr>{% endfor %}</table></div></section>"""
    return page(body,"Student dashboard",s=s,docs=docs,history=history)

def get_doc(did):
    s=student()
    with db() as c: d=c.execute("SELECT * FROM documents WHERE id=? AND class_id=?",(did,s["class_id"])).fetchone()
    if not d: abort(404)
    return s,d

@app.route("/document/<int:did>/view")
@need_student
def view_doc(did):
    s,d=get_doc(did); log(s["username"],"VIEWED",d["filename"],s["id"])
    if d["web_link"]: return redirect(d["web_link"])
    return redirect(url_for("download_doc",did=did))

@app.route("/document/<int:did>/download")
@need_student
def download_doc(did):
    s,d=get_doc(did); log(s["username"],"DOWNLOADED",d["filename"],s["id"])
    if d["drive_id"]:
        try:
            stream,name,mime=drive_download(d["drive_id"])
            return send_file(stream,as_attachment=True,download_name=name,mimetype=mime)
        except Exception: app.logger.exception("Drive download failed"); abort(502)
    if d["local_path"] and Path(d["local_path"]).exists(): return send_file(d["local_path"],as_attachment=True,download_name=d["filename"])
    abort(404)

@app.errorhandler(413)
def too_big(e):
    flash("Upload too large. Limit is 50 MB per request.","error")
    return redirect(url_for("admin" if session.get("role")=="admin" else "index"))

# Startup order matters: restore a known-good Drive backup before creating a fresh DB.
# If Drive is unavailable or no backup exists, the app starts normally with a new DB.
try:
    restore_database_from_drive()
except Exception:
    app.logger.exception("Database restore from Google Drive failed; initializing local database")
init_db()
_backup_suspended = False

if __name__=="__main__":
    app.run(host="127.0.0.1",port=int(os.environ.get("PORT","5000")),debug=False)
