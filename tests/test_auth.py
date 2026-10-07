import time
import pytest
import dns.resolver
import app as module


@pytest.fixture
def client(tmp_path, monkeypatch):
    module.app.config.update(TESTING=True, DATABASE=str(tmp_path / 'users.db'))
    monkeypatch.setattr(module.dns.resolver, 'resolve', lambda *a, **k: [True])
    return module.app.test_client()


def post(client, path, data):
    client.get(path)
    with client.session_transaction() as s:
        token = s['csrf']
    return client.post(path, data={**data, 'csrf': token}, follow_redirects=True)


def test_complete_flow(client):
    response = post(client, '/registro', {'email': 'ana@example.com', 'password': 'Seguro123!', 'confirm': 'Seguro123!'})
    assert b'Configura tu segundo factor' in response.data
    with client.session_transaction() as s:
        secret = s['enrollment']['secret']
    assert client.get('/panel').status_code == 302
    # Protected-route denial clears the unauthenticated session; enroll again.
    post(client, '/registro', {'email': 'ana@example.com', 'password': 'Seguro123!', 'confirm': 'Seguro123!'})
    with client.session_transaction() as s:
        secret = s['enrollment']['secret']
    assert b'Ya est' not in post(client, '/mfa', {'code': 'abcdef'}).data
    counter = int(time.time()) // 30
    response = post(client, '/mfa', {'code': module.totp(secret, counter)})
    assert b'Acceso exitoso' in response.data
    with module.db() as conn:
        user = conn.execute('SELECT * FROM users').fetchone()
        assert user['password'].startswith('scrypt:')
        assert user['password'] != 'Seguro123!'
    post(client, '/salir', {})
    assert client.get('/panel').status_code == 302
    assert b'Correo o' in post(client, '/', {'email': 'ana@example.com', 'password': 'incorrecta'}).data
    response = post(client, '/', {'email': 'ana@example.com', 'password': 'Seguro123!'})
    assert 'ltimo paso' in response.data.decode()
    assert b'ya utilizado' in post(client, '/mfa', {'code': module.totp(secret, counter)}).data
    # Simulate the next authenticator time step, accepted within clock tolerance.
    assert b'Acceso exitoso' in post(client, '/mfa', {'code': module.totp(secret, counter + 1)}).data


def test_invalid_inputs(client, monkeypatch):
    assert b'correo electr' in post(client, '/', {'email': 'mal', 'password': 'abcdefgh'}).data
    assert b'entre 8 y 128' in post(client, '/registro', {'email': 'ana@example.com', 'password': '123', 'confirm': '123'}).data
    def missing(*args, **kwargs):
        raise dns.resolver.NXDOMAIN()
    monkeypatch.setattr(module.dns.resolver, 'resolve', missing)
    assert b'dominio del correo no existe' in post(client, '/', {'email': 'ana@dominio.invalid', 'password': 'abcdefgh'}).data


def test_csrf_and_limits(client):
    assert client.post('/', data={}).status_code == 400
    for _ in range(5):
        post(client, '/', {'email': 'nadie@example.com', 'password': 'incorrecta'})
    assert b'Demasiados intentos' in post(client, '/', {'email': 'nadie@example.com', 'password': 'incorrecta'}).data


def test_totp_standard_vector():
    import base64
    secret = base64.b32encode(b'12345678901234567890').decode()
    assert module.totp(secret, 1) == '287082'


def test_https_dns_fallback(monkeypatch):
    import io
    def timeout(*args, **kwargs):
        raise dns.resolver.LifetimeTimeout()
    monkeypatch.setattr(module.dns.resolver, 'resolve', timeout)
    monkeypatch.setattr(module.urllib.request, 'urlopen', lambda *a, **k: io.BytesIO(b'{"Status":0,"Answer":[{"type":15}]}'))
    assert module.validate_email('ana@example.com') == 'ana@example.com'
    monkeypatch.setattr(module.urllib.request, 'urlopen', lambda *a, **k: io.BytesIO(b'{"Status":3}'))
    with pytest.raises(ValueError, match='no existe'):
        module.validate_email('ana@dominio.invalid')
