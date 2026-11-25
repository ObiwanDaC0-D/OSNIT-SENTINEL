"""Single-user, loopback-only research notebook. No remote fetching of user URLs."""
import hashlib
import json
import os
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from urllib.parse import quote, urlparse

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator
from starlette.middleware.trustedhost import TrustedHostMiddleware
from sentinel.research import collect

STATIC = Path(__file__).parent / 'static'

def now():
    return datetime.now(timezone.utc).isoformat()

class Case(BaseModel):
    title: str = Field(min_length=1, max_length=150)
    purpose: str = Field(min_length=10, max_length=2000)
    scope: Literal['self-audit', 'authorized-audit', 'public-research']

class Evidence(BaseModel):
    title: str = Field(min_length=1, max_length=250)
    source: str = Field(max_length=2000)
    notes: str = Field(default='', max_length=20000)
    event_date: str = ''
    status: Literal['unverified', 'possible', 'corroborated', 'verified', 'contradicted'] = 'unverified'
    rationale: str = Field(default='', max_length=2000)

    @field_validator('source')
    @classmethod
    def source_url(cls, value):
        parsed = urlparse(value)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError('Use a public http(s) citation without credentials')
        return value

    @field_validator('event_date')
    @classmethod
    def date_valid(cls, value):
        if value:
            datetime.strptime(value, '%Y-%m-%d')
        return value

class Relationship(BaseModel):
    source_id: int
    target_id: int
    label: str = Field(min_length=1, max_length=150)
    rationale: str = Field(min_length=10, max_length=2000)

class Research(BaseModel):
    kind: Literal['username', 'professional', 'document', 'domain']
    query: str = Field(min_length=2, max_length=200)
    consent: bool = False


def create_app(db_path=None):
    path = Path(db_path or os.environ.get('SENTINEL_DB', str(Path.home() / '.local/share/sentinel/cases.sqlite3'))).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    @contextmanager
    def db():
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA foreign_keys=ON')
        try:
            with conn:
                yield conn
        finally:
            conn.close()
    with db() as conn:
        conn.executescript('''
        CREATE TABLE IF NOT EXISTS cases(id INTEGER PRIMARY KEY, title TEXT, purpose TEXT, scope TEXT, created TEXT);
        CREATE TABLE IF NOT EXISTS evidence(id INTEGER PRIMARY KEY, case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE,
          title TEXT, source TEXT, notes TEXT, event_date TEXT, status TEXT, rationale TEXT, captured TEXT, sha256 TEXT);
        CREATE TABLE IF NOT EXISTS links(id INTEGER PRIMARY KEY, case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE,
          source_id INTEGER REFERENCES evidence(id) ON DELETE CASCADE, target_id INTEGER REFERENCES evidence(id) ON DELETE CASCADE,
          label TEXT, rationale TEXT);
        ''')
    os.chmod(path, 0o600)
    app = FastAPI(title='Sentinel OSINT Research Lab', docs_url=None, redoc_url=None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=['localhost', '127.0.0.1', '[::1]', 'testserver'])

    @app.middleware('http')
    async def local_guard(request: Request, call_next):
        origin = request.headers.get('origin')
        if request.client and request.client.host not in ('127.0.0.1', '::1', 'testclient'):
            return JSONResponse({'detail': 'Loopback access only'}, status_code=403)
        if origin and origin != str(request.base_url).rstrip('/'):
            return JSONResponse({'detail': 'Cross-origin access denied'}, status_code=403)
        if request.method in ('POST', 'PUT', 'DELETE') and request.headers.get('x-sentinel') != 'local':
            return JSONResponse({'detail': 'Local request header required'}, status_code=403)
        response = await call_next(request)
        response.headers.update({'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
            'Referrer-Policy': 'no-referrer', 'Content-Security-Policy': "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"})
        return response

    def require_case(conn, cid):
        row = conn.execute('SELECT * FROM cases WHERE id=?', (cid,)).fetchone()
        if not row:
            raise HTTPException(404, 'Case not found')
        return dict(row)

    @app.get('/api/cases')
    def cases():
        with db() as conn:
            return [dict(r) for r in conn.execute('SELECT * FROM cases ORDER BY id DESC')]

    @app.post('/api/cases', status_code=201)
    def new_case(item: Case):
        with db() as conn:
            cursor = conn.execute('INSERT INTO cases(title,purpose,scope,created) VALUES(?,?,?,?)', (*item.model_dump().values(), now()))
            return {'id': cursor.lastrowid}

    @app.get('/api/cases/{cid}')
    def detail(cid: int):
        with db() as conn:
            case = require_case(conn, cid)
            return {'case': case, 'evidence': [dict(r) for r in conn.execute('SELECT * FROM evidence WHERE case_id=? ORDER BY event_date,id', (cid,))],
                    'links': [dict(r) for r in conn.execute('SELECT * FROM links WHERE case_id=?', (cid,))]}

    @app.delete('/api/cases/{cid}')
    def delete_case(cid: int):
        with db() as conn:
            require_case(conn, cid)
            conn.execute('DELETE FROM cases WHERE id=?', (cid,))
        return {'deleted': True}

    @app.post('/api/cases/{cid}/evidence', status_code=201)
    def add_evidence(cid: int, item: Evidence):
        if item.status != 'unverified' and len(item.rationale.strip()) < 10:
            raise HTTPException(422, 'Explain the verification classification (10 characters minimum)')
        payload = item.model_dump()
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        with db() as conn:
            require_case(conn, cid)
            cur = conn.execute('INSERT INTO evidence(case_id,title,source,notes,event_date,status,rationale,captured,sha256) VALUES(?,?,?,?,?,?,?,?,?)',
                (cid, *payload.values(), now(), digest))
            return {'id': cur.lastrowid, 'sha256': digest}

    @app.post('/api/cases/{cid}/links', status_code=201)
    def add_link(cid: int, item: Relationship):
        with db() as conn:
            require_case(conn, cid)
            ids = {r[0] for r in conn.execute('SELECT id FROM evidence WHERE case_id=?', (cid,))}
            if item.source_id == item.target_id or not {item.source_id, item.target_id} <= ids:
                raise HTTPException(422, 'Choose two different evidence records in this case')
            cur = conn.execute('INSERT INTO links(case_id,source_id,target_id,label,rationale) VALUES(?,?,?,?,?)', (cid, *item.model_dump().values()))
            return {'id': cur.lastrowid}

    @app.get('/api/cases/{cid}/report')
    def report(cid: int):
        return JSONResponse(detail(cid), headers={'Content-Disposition': f'attachment; filename="sentinel-case-{cid}.json"'})

    @app.post('/api/cases/{cid}/research')
    async def research(cid: int, item: Research):
        with db() as conn:
            case = require_case(conn, cid)
        if not item.consent:
            raise HTTPException(422, 'Confirm authorized scope and external provider disclosure')
        q = item.query.strip()
        if item.kind == 'username':
            if case['scope'] == 'public-research':
                raise HTTPException(403, 'Username checks require an audit case')
            if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9-]{0,38}', q):
                raise HTTPException(422, 'Enter a GitHub username')
            url = 'https://api.github.com/users/' + quote(q, safe='')
            try:
                async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
                    result = await client.get(url, headers={'Accept': 'application/vnd.github+json', 'User-Agent': 'Sentinel-Local-Research'})
                if result.status_code == 404:
                    return {'findings': [], 'message': 'No GitHub account found; this says nothing about other providers.'}
                result.raise_for_status()
                finding = {'title': 'GitHub username candidate', 'source': 'https://github.com/' + quote(q), 'notes': 'Public account exists. Username match is not identity proof.', 'status': 'unverified'}
                finding['notes'] += '\nAvailability: publicly accessible\nChecked: ' + now()
                saved = add_evidence(cid, Evidence(**finding))
                finding.update(evidence_id=saved['id'], availability='publicly accessible')
                return {'findings': [finding], 'message': 'Candidate saved as unverified evidence.'}
            except httpx.HTTPError:
                raise HTTPException(502, 'Provider unavailable or rate limited; no conclusion can be drawn')
        if item.kind == 'domain':
            q = q.lower().rstrip('.')
            if not re.fullmatch(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}', q):
                raise HTTPException(422, 'Enter a public domain name, without a URL or IP address')
        result = await collect(item.kind, q)
        # Save automatic findings as unverified evidence; keep exact repeats out.
        for finding in result['findings']:
            finding['notes'] += "\nAvailability: " + finding['availability'] + "\nChecked: " + finding['checked']
            with db() as conn:
                existing = conn.execute('SELECT id FROM evidence WHERE case_id=? AND source=? AND title=?',
                    (cid, finding['source'], finding['title'])).fetchone()
            if existing:
                finding['evidence_id'] = existing['id']
                finding['saved'] = False
            else:
                saved = add_evidence(cid, Evidence(**{k:v for k,v in finding.items() if k in Evidence.model_fields}))
                finding['evidence_id'] = saved['id']
                finding['saved'] = True
        return result

    @app.get('/api/email-check')
    def email_check():
        return {'url': 'https://haveibeenpwned.com/', 'message': 'Use the provider’s email verification and notification flow for an address you control. Sentinel never accepts or stores an email address or breach records. Record only a minimal audit conclusion after verification.'}

    app.mount('/static', StaticFiles(directory=STATIC), name='static')
    @app.get('/')
    def index():
        return FileResponse(STATIC / 'index.html')
    return app
