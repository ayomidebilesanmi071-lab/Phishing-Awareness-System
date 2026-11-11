# CMIMS - Computer Maintenance & Inventory Management System

The application lives in `computer_maintenance_system/` and has its **own**
virtualenv at `computer_maintenance_system/.venv` (Flask + SQLAlchemy + pytest).
The `app.py`, `models/`, `routes/` etc. at the repository root belong to an
older, unrelated app (PARS) and are not used by this preview.

## How to reproduce artifacts

```bash
cd computer_maintenance_system

# 1. Virtualenv (skip if .venv already exists)
python -m venv .venv

# 2. Dependencies
.venv/Scripts/python.exe -m pip install -r requirements.txt

# 3. Optional local config (copy, then edit values; .env is git-ignored)
cp .env.example .env

# 4. Database + sample data (both commands are idempotent)
.venv/Scripts/python.exe -m flask --app app init-db
.venv/Scripts/python.exe -m flask --app app seed-db
```

The SQLite database is created at `computer_maintenance_system/instance/computer_maintenance.db`.
`DATABASE_URL` overrides it; uploads go to `instance/uploads/`.

## How to run the server

```bash
cd computer_maintenance_system
.venv/Scripts/python.exe app.py          # http://127.0.0.1:5000
```

* Host: `HOST` environment variable, default `127.0.0.1`.
* Port: `PORT` environment variable, default `5000`.
* Debug mode is opt-in (`FLASK_DEBUG=1`); a plain run never exposes the Werkzeug
  debugger.

Tests:

```bash
cd computer_maintenance_system
.venv/Scripts/python.exe -m pytest -q
```

## Demo accounts (development only - change before deploying)

| Role           | Email                | Password         |
|----------------|----------------------|------------------|
| Administrator  | admin@cmims.local    | Admin@2026#ICT   |
| ICT Officer    | officer1@cmims.local | Officer@2026#One |
| ICT Officer    | officer2@cmims.local | Officer@2026#Two |
| Viewer         | viewer@cmims.local   | Viewer@2026#One  |

## Preview

Registered in the Preview tab at <http://127.0.0.1:5000/>. Port 5000 is the app
default and was free, so no port override was needed.

Start it detached from the **repository root** (Windows, `Start-Process` prints the pid):

```powershell
powershell -NoProfile -Command "(Start-Process -FilePath '<root>\computer_maintenance_system\.venv\Scripts\python.exe' -ArgumentList 'app.py' -WorkingDirectory '<root>\computer_maintenance_system' -RedirectStandardOutput '<root>\.freebuff\preview-fa14516c-477f-4f61-94f7-8a73361c2e5b.log' -RedirectStandardError '<root>\.freebuff\preview-fa14516c-477f-4f61-94f7-8a73361c2e5b.log.err' -WindowStyle Hidden -PassThru).Id"
```

Note: the wrapper shell can report a timeout even though the server starts fine —
verify with `netstat -ano | grep ":5000 " | grep LISTENING`, check the pid with
`Get-Process -Id <pid>`, then curl `http://127.0.0.1:5000/login` for a 200 before
registering. `/` answers 302 to `/login` when signed out.

Server log:

```
.freebuff/preview-fa14516c-477f-4f61-94f7-8a73361c2e5b.log      (stdout)
.freebuff/preview-fa14516c-477f-4f61-94f7-8a73361c2e5b.log.err  (stderr + request log)
```

The database at `computer_maintenance_system/instance/computer_maintenance.db` is
**not** tracked by git (this directory is not a git repository at all) but already exists
in the workspace and holds the demo data, so `init-db` / `seed-db` only need running when
it is missing. `instance/uploads/` likewise ships with placeholder content.
