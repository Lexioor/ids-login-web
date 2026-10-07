import base64
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import struct
import time
import json
import urllib.request
import urllib.parse
from pathlib import Path

import dns.resolver
from flask import Flask, abort, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from flask_session import Session
from cachelib.file import FileSystemCache

app = Flask(__name__)
Path(app.instance_path).mkdir(exist_ok=True)
os.chmod(app.instance_path, 0o700)
key_path = Path(app.instance_path) / 'session.key'
if not key_path.exists():
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(secrets.token_bytes(32))
app.config.update(SECRET_KEY=key_path.read_bytes(), DATABASE=str(Path(app.instance_path) / 'users.db'),
                  SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Strict',
                  SESSION_COOKIE_SECURE=os.getenv('COOKIE_SECURE') == '1', MAX_CONTENT_LENGTH=16384)
app.config.update(SESSION_TYPE='cachelib', SESSION_CACHELIB=FileSystemCache(str(Path(app.instance_path) / 'sessions'), mode=0o600), SESSION_PERMANENT=False)
Session(app)


def db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    conn.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT UNIQUE, password TEXT, secret TEXT, last_counter INTEGER DEFAULT -1)')
    conn.execute('CREATE TABLE IF NOT EXISTS attempts (identity TEXT PRIMARY KEY, count INTEGER, since REAL)')
    return conn


def validate_email(value):
    value = value.strip().lower()
    if len(value) > 254 or not re.fullmatch(r'[a-z0-9.!#$%&\x27*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+', value):
        raise ValueError('Introduce un correo electrónico válido.')
    if '..' in value.split('@')[0] or value.startswith('.') or value.split('@')[0].endswith('.'):
        raise ValueError('Introduce un correo electrónico válido.')
    domain = value.split('@')[1]
    try:
        # An SOA answer, including an enclosing zone, is insufficient: ask for
        # records on the exact domain. DNS existence does not prove mailbox ownership.
        for kind in ('MX', 'A', 'AAAA'):
            try:
                if dns.resolver.resolve(domain, kind, lifetime=4):
                    return value
            except dns.resolver.NoAnswer:
                continue
    except dns.resolver.NXDOMAIN:
        raise ValueError('El dominio del correo no existe.') from None
    except (dns.exception.DNSException, OSError):
        # Cloud environments may disallow UDP DNS; use TLS-verified HTTPS
        # through the platform proxy, without bypassing network restrictions.
        try:
            for kind in ('MX', 'A', 'AAAA'):
                url = 'https://cloudflare-dns.com/dns-query?' + urllib.parse.urlencode({'name': domain, 'type': kind})
                query = urllib.request.Request(url, headers={'Accept': 'application/dns-json'})
                with urllib.request.urlopen(query, timeout=5) as response:
                    result = json.load(response)
                if result.get('Status') == 3:
                    raise ValueError('El dominio del correo no existe.')
                if result.get('Status') != 0:
                    raise OSError('DNS lookup failed')
                if any(record.get('type') in (1, 15, 28) for record in result.get('Answer', [])):
                    return value
        except (OSError, json.JSONDecodeError):
            raise ValueError('No pudimos verificar el dominio. Inténtalo de nuevo.') from None
    raise ValueError('El dominio no tiene registros de correo o dirección válidos.')


def totp(secret, counter):
    digest = hmac.new(base64.b32decode(secret), struct.pack('>Q', counter), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return f'{(struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff) % 1000000:06d}'


def verify_totp(secret, code, last=-1):
    if not re.fullmatch(r'\d{6}', code):
        return None
    now = int(time.time()) // 30
    for counter in (now - 1, now, now + 1):
        if counter > last and hmac.compare_digest(totp(secret, counter), code):
            return counter
    return None


def limited(identity):
    with db() as conn:
        row = conn.execute('SELECT * FROM attempts WHERE identity=?', (identity,)).fetchone()
        if row and time.time() - row['since'] < 300:
            if row['count'] >= 5:
                return True
            conn.execute('UPDATE attempts SET count=count+1 WHERE identity=?', (identity,))
        else:
            conn.execute('INSERT OR REPLACE INTO attempts VALUES (?, 1, ?)', (identity, time.time()))
    return False


@app.before_request
def csrf():
    if 'csrf' not in session:
        session['csrf'] = secrets.token_urlsafe(32)
    if request.method == 'POST' and not hmac.compare_digest(session['csrf'], request.form.get('csrf', '')):
        abort(400)


@app.after_request
def headers(response):
    response.headers.update({'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
                             'X-Frame-Options': 'DENY', 'Referrer-Policy': 'same-origin',
                             'Content-Security-Policy': "default-src 'self'; style-src 'self'; form-action 'self'; frame-ancestors 'none'"})
    return response


@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        try:
            email = validate_email(request.form.get('email', ''))
            if limited('login:' + email):
                raise ValueError('Demasiados intentos. Espera 5 minutos.')
            with db() as conn:
                user = conn.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
            if not user or not check_password_hash(user['password'], request.form.get('password', '')):
                raise ValueError('Correo o contraseña incorrectos.')
            session.clear()
            session.update(pending=user['id'], expires=time.time() + 300)
            app.session_interface.regenerate(session)
            return redirect(url_for('mfa'))
        except ValueError as e:
            error = str(e)
    return render_template('auth.html', mode='login', error=error)


@app.route('/registro', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        try:
            email = validate_email(request.form.get('email', ''))
            password = request.form.get('password', '')
            if not 8 <= len(password) <= 128:
                raise ValueError('La contraseña debe tener entre 8 y 128 caracteres.')
            if password != request.form.get('confirm', ''):
                raise ValueError('Las contraseñas no coinciden.')
            with db() as conn:
                if conn.execute('SELECT id FROM users WHERE email=?', (email,)).fetchone():
                    raise ValueError('No se pudo registrar este correo. Intenta iniciar sesión.')
            # Store only the hash during the short enrollment; no account exists yet.
            session.clear()
            session.update(enrollment={'email': email, 'password': generate_password_hash(password, method='scrypt'),
                                       'secret': base64.b32encode(secrets.token_bytes(20)).decode()}, expires=time.time() + 300)
            app.session_interface.regenerate(session)
            return redirect(url_for('mfa'))
        except ValueError as e:
            error = str(e)
    return render_template('auth.html', mode='register', error=error)


@app.route('/mfa', methods=['GET', 'POST'])
def mfa():
    enrollment = session.get('enrollment')
    pending = session.get('pending')
    if (not enrollment and not pending) or session.get('expires', 0) < time.time():
        session.clear()
        return redirect(url_for('login'))
    error = None
    if request.method == 'POST':
        identity = 'mfa:' + (enrollment['email'] if enrollment else str(pending))
        if limited(identity):
            error = 'Demasiados intentos. Espera 5 minutos y vuelve a iniciar sesión.'
        else:
            with db() as conn:
                user = None if enrollment else conn.execute('SELECT * FROM users WHERE id=?', (pending,)).fetchone()
                counter = verify_totp(enrollment['secret'] if enrollment else user['secret'], request.form.get('code', ''), -1 if enrollment else user['last_counter'])
                if counter is None:
                    error = 'Código incorrecto o ya utilizado. Usa el código actual de tu app.'
                else:
                    if enrollment:
                        try:
                            cursor = conn.execute('INSERT INTO users(email,password,secret,last_counter) VALUES (?,?,?,?)',
                                                  (enrollment['email'], enrollment['password'], enrollment['secret'], counter))
                            uid = cursor.lastrowid
                        except sqlite3.IntegrityError:
                            session.clear()
                            return redirect(url_for('login'))
                    else:
                        cursor = conn.execute('UPDATE users SET last_counter=? WHERE id=? AND last_counter<?', (counter, pending, counter))
                        if cursor.rowcount != 1:
                            abort(400)
                        uid = pending
                    session.clear()
                    session.update(uid=uid, authenticated_at=time.time())
                    app.session_interface.regenerate(session)
                    return redirect(url_for('dashboard'))
    return render_template('auth.html', mode='mfa', enrollment=enrollment, error=error)


@app.get('/panel')
def dashboard():
    if not session.get('uid') or time.time() - session.get('authenticated_at', 0) > 3600:
        session.clear()
        return redirect(url_for('login'))
    with db() as conn:
        user = conn.execute('SELECT email FROM users WHERE id=?', (session['uid'],)).fetchone()
    if not user:
        session.clear()
        return redirect(url_for('login'))
    return render_template('auth.html', mode='dashboard', email=user['email'])


@app.post('/salir')
def logout():
    session.clear()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
