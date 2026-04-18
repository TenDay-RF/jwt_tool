import base64, json, subprocess, sys

def b64(data):
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b'=').decode()

def tok(header, payload, sig='x'):
    return f"{b64(header)}.{b64(payload)}.{sig}"

def run(*args):
    return subprocess.check_output([sys.executable, 'jwt_tool_enhanced.py', *args], text=True)

def test_rfc_none_detected():
    out = run('--rfc8725-audit', tok({'alg':'none','typ':'JWT'}, {'sub':'1'}))
    assert 'alg=none present' in out

def test_oidc_hint_missing_typ():
    out = run('--oidc-hints', tok({'alg':'RS256','typ':'JWT'}, {'iss':'x','aud':'y'}))
    assert 'typ is not at+jwt' in out

def test_profile_nonce_confusion():
    out = run('--oidc-hints', tok({'alg':'RS256','typ':'JWT'}, {'iss':'https://issuer.example.com','aud':'my-client-id','nonce':'abc'}), '--profile', 'profiles/api-access-token.yaml')
    assert 'expects access token' in out
