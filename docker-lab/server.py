#!/usr/bin/env python3
import base64, hashlib, hmac, json, time
from http.server import BaseHTTPRequestHandler, HTTPServer
SECRET = b'super-secret-lab-key-which-is-long-enough'
ISS = 'jwt-lab'
AUD = 'jwt-lab-admin'
KEYS = {'safe': SECRET}
def b64(x): return base64.urlsafe_b64encode(x).rstrip(b'=').decode()
def decode(seg): seg += '=' * (-len(seg) % 4); return json.loads(base64.urlsafe_b64decode(seg.encode()).decode())
def sign(msg,key): return b64(hmac.new(key, msg, hashlib.sha256).digest())
def issue(payload, alg='HS256', kid='safe', key=None):
    if alg == 'none':
        h=b64(json.dumps({'alg':'none','typ':'JWT'}).encode()); p=b64(json.dumps(payload).encode()); return f'{h}.{p}.'
    h=b64(json.dumps({'alg':'HS256','typ':'JWT','kid':kid}).encode()); p=b64(json.dumps(payload).encode()); s=sign(f'{h}.{p}'.encode(), key or KEYS.get(kid, SECRET)); return f'{h}.{p}.{s}'
class H(BaseHTTPRequestHandler):
    def _j(self,code,obj):
        body=json.dumps(obj).encode(); self.send_response(code); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        now=int(time.time())+3600
        if self.path=='/issue/safe-admin': return self._j(200, {'token': issue({'sub':'1','role':'admin','iss':ISS,'aud':AUD,'exp':now})})
        if self.path=='/issue/unsafe-none-admin': return self._j(200, {'token': issue({'sub':'9','role':'admin','iss':ISS,'aud':AUD,'exp':now}, alg='none')})
        if self.path=='/issue/unsafe-kid-admin': return self._j(200, {'token': issue({'sub':'8','role':'admin','iss':ISS,'aud':AUD,'exp':now}, kid='missing-dev', key=b'fallback-dev-key')})
        if self.path=='/issue/id-token':
            payload={'sub':'u1','iss':ISS,'aud':'my-client-id','exp':now,'nonce':'abc123','email':'user@example.test'}
            return self._j(200, {'token': issue(payload)})
        auth=self.headers.get('Authorization','')
        tok=auth.replace('Bearer ','',1) if auth.startswith('Bearer ') else ''
        try:
            parts=tok.split('.')
            header=decode(parts[0]); payload=decode(parts[1])
        except Exception:
            return self._j(401, {'ok':False,'detail':'bad format'})
        if self.path=='/admin/unsafe-none':
            if header.get('alg')=='none' and payload.get('role')=='admin': return self._j(200, {'ok':True,'detail':'accepted none'})
            return self._j(401, {'ok':False,'detail':'denied'})
        if self.path=='/admin/unsafe-kid':
            key = KEYS.get(str(header.get('kid')), b'fallback-dev-key')
            sig = sign(f'{parts[0]}.{parts[1]}'.encode(), key)
            if sig == parts[2] and payload.get('role') == 'admin': return self._j(200, {'ok':True,'detail':'accepted fallback kid'})
            return self._j(401, {'ok':False,'detail':'denied'})
        if self.path=='/api/confused-oidc':
            if payload.get('nonce') and payload.get('aud') == 'my-client-id': return self._j(200, {'ok':True,'detail':'accepted likely ID token'})
            return self._j(401, {'ok':False,'detail':'denied'})
        return self._j(404, {'error':'not found'})
HTTPServer(('0.0.0.0',8087),H).serve_forever()
