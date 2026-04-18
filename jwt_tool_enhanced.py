#!/usr/bin/env python3
import argparse, base64, json, os, sys

SEV_TEXT = {
    'critical': 'Критично',
    'high': 'Высокий риск',
    'medium': 'Средний риск',
    'low': 'Низкий риск',
    'info': 'Информация'
}

def safe_b64json(seg):
    try:
        seg += '=' * (-len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(seg.encode()).decode('utf-8'))
    except Exception:
        return None

def token_kind(tok):
    n = len(tok.split('.'))
    return 'JWS' if n == 3 else 'JWE' if n == 5 else 'unknown'

def sev_score(sev):
    return {'critical':40,'high':20,'medium':10,'low':5,'info':0}.get(sev,0)

def load_profile(path):
    if not path:
        return None
    txt = open(path, 'r', encoding='utf-8').read()
    try:
        import yaml
        return yaml.safe_load(txt)
    except Exception:
        return json.loads(txt)

def html_report(title, data):
    esc = json.dumps(data, ensure_ascii=False, indent=2)
    return f'<!doctype html><html><head><meta charset="utf-8"><title>{title}</title><style>body{{font-family:system-ui,sans-serif;background:#0b1020;color:#e6edf3;margin:2rem}}pre{{white-space:pre-wrap;background:#11182c;padding:1rem;border-radius:12px;border:1px solid #334}}</style></head><body><h1>{title}</h1><pre>{esc}</pre></body></html>'

def save_report(base, data):
    os.makedirs('reports', exist_ok=True)
    j = os.path.join('reports', base + '.json')
    h = os.path.join('reports', base + '.html')
    open(j,'w',encoding='utf-8').write(json.dumps(data, ensure_ascii=False, indent=2))
    open(h,'w',encoding='utf-8').write(html_report(base, data))
    return {'json': j, 'html': h}

def rfc8725_audit(token, profile=None):
    issues, notes, next_steps = [], [], []
    kind = token_kind(token)
    parts = token.split('.')
    header = safe_b64json(parts[0]) if len(parts) > 0 else None
    payload = safe_b64json(parts[1]) if len(parts) > 1 and kind == 'JWS' else None
    if kind == 'unknown':
        issues.append({'severity':'high','title':'Неверный формат compact JWT/JWE','meaning':'Токен не похож на стандартный JWT/JWE compact serialization.'})
        next_steps.append('Проверь, что токен целиком скопирован и состоит из 3 частей для JWS или 5 частей для JWE.')
        return {'mode':'RFC8725 AUDIT','kind':kind,'issues':issues,'notes':notes,'header':header,'payload':payload,'score':20,'next_steps':next_steps,'summary':'Токен имеет некорректный формат.'}
    if not isinstance(header, dict):
        issues.append({'severity':'high','title':'Заголовок не декодируется как JSON','meaning':'Первая часть токена не похожа на Base64url JSON header.'})
        next_steps.append('Проверь, не повреждён ли токен и действительно ли это JWT/JWE.')
        return {'mode':'RFC8725 AUDIT','kind':kind,'issues':issues,'notes':notes,'header':header,'payload':payload,'score':20,'next_steps':next_steps,'summary':'Нельзя корректно прочитать header токена.'}
    alg = str(header.get('alg',''))
    typ = header.get('typ')
    if alg.lower() == 'none':
        issues.append({'severity':'critical','title':'alg=none','meaning':'Токен объявлен как неподписанный. Если сервер его примет, это может дать обход проверки подписи.'})
        next_steps.append('Если у тебя есть локальный стенд, проверь приём токена на endpoint, который читает Authorization: Bearer.')
    if typ not in (None,'JWT','at+jwt','application/at+jwt'):
        issues.append({'severity':'medium','title':f'Нетипичный typ: {typ}','meaning':'Тип токена нестандартный. Это не всегда баг, но стоит проверить логику маршрутизации токенов.'})
    for hk in ('jku','x5u','jwk'):
        if hk in header:
            issues.append({'severity':'high','title':f'Опасный JOSE header: {hk}','meaning':'Сервер не должен слепо доверять URL/ключам из присланного токена.'})
            next_steps.append(f'Проверь, использует ли приложение {hk} из токена без allowlist.')
    if 'kid' in header:
        kid = str(header['kid'])
        if any(x in kid for x in ('../','..\\','/','\\',';','|','$(','`')):
            issues.append({'severity':'high','title':'Подозрительный kid','meaning':'Значение kid похоже на path traversal / command injection / небезопасный lookup ключа.','value':kid})
            next_steps.append('Проверь endpoint из docker-lab /admin/unsafe-kid или аналогичную серверную логику выбора ключа.')
        else:
            notes.append('kid присутствует: на сервере должен быть строгий allowlist допустимых значений.')
    if isinstance(payload, dict):
        for claim in ('exp','iss','aud'):
            if claim not in payload:
                issues.append({'severity':'medium','title':f'Нет claim {claim}','meaning':'Для безопасной валидации обычно важны exp, iss и aud.'})
        if payload.get('nonce') and typ in (None, 'JWT'):
            notes.append('Есть nonce: токен может быть ближе к OIDC ID Token, чем к access token.')
        if payload.get('client_id') or payload.get('scope') or payload.get('azp'):
            notes.append('Есть признаки access token / OAuth-контекста.')
    if profile:
        for c in profile.get('required_claims', []):
            if not isinstance(payload, dict) or c not in payload:
                issues.append({'severity':'high','title':f'Профиль требует claim {c}','meaning':'По профилю сервиса этот claim обязателен, но в токене его нет.'})
        allowed = [str(x).lower() for x in profile.get('allowed_algs', [])]
        if allowed and alg.lower() not in allowed:
            issues.append({'severity':'critical','title':f'Алгоритм не разрешён профилем: {alg}','meaning':'Для этого сервиса ожидается другой алгоритм подписи.'})
        if profile.get('require_typ') and typ != profile.get('require_typ'):
            issues.append({'severity':'high','title':f'typ не совпадает с профилем','meaning':f'Ожидался typ={profile.get("require_typ")}, но получен {typ}.'})
        if isinstance(payload, dict):
            if profile.get('issuer') and payload.get('iss') != profile.get('issuer'):
                issues.append({'severity':'high','title':'iss не совпадает с профилем','meaning':'Токен выдан не тем issuer, который ожидает сервис.'})
            if profile.get('audience') and payload.get('aud') != profile.get('audience'):
                issues.append({'severity':'high','title':'aud не совпадает с профилем','meaning':'Токен предназначен не для того сервиса, который ты проверяешь.'})
    score = min(sum(sev_score(i['severity']) for i in issues), 100)
    summary = 'Серьёзных проблем не найдено.' if not issues else 'Найдены признаки небезопасной обработки JWT или несоответствия политике.'
    if not next_steps:
        next_steps.append('Если это токен API, прогони его ещё через --oidc-hints и, при наличии профиля, укажи --profile.')
    return {'mode':'RFC8725 AUDIT','kind':kind,'issues':issues,'notes':notes,'header':header,'payload':payload,'score':score,'next_steps':next_steps,'summary':summary}

def jwe_audit(token):
    parts = token.split('.')
    out = {'mode':'JWE PASSIVE AUDIT','kind': token_kind(token), 'issues': [], 'notes': [], 'next_steps': []}
    if out['kind'] != 'JWE':
        out['issues'].append({'severity':'info','title':'Это не JWE','meaning':'Режим JWE полезен только для токенов из 5 частей.'})
        out['score'] = 0
        out['summary'] = 'Передан не JWE-токен.'
        out['next_steps'].append('Используй --rfc8725-audit для обычного JWT/JWS.')
        return out
    header = safe_b64json(parts[0]); out['header']=header
    if not isinstance(header, dict):
        out['issues'].append({'severity':'high','title':'JWE header не декодируется','meaning':'Первая часть JWE не похожа на Base64url JSON.'})
        out['score']=20; out['summary']='Нельзя корректно прочитать JWE header.'; return out
    alg = header.get('alg'); enc = header.get('enc'); zipv = header.get('zip')
    if alg == 'RSA1_5': out['issues'].append({'severity':'critical','title':'Используется RSA1_5','meaning':'Это legacy-алгоритм, который исторически связан с Bleichenbacher-style рисками.'})
    if alg in ('ECDH-ES','ECDH-ES+A128KW','ECDH-ES+A192KW','ECDH-ES+A256KW'): out['issues'].append({'severity':'high','title':'Используется ECDH-ES','meaning':'Нужно проверить защиту от invalid curve и корректную обработку epk.'})
    if alg and str(alg).startswith('PBES2-'): out['issues'].append({'severity':'high','title':'Используется PBES2','meaning':'Нужно проверить ограничение p2c, иначе возможен DoS по CPU.'})
    if isinstance(header.get('p2c'), int) and header.get('p2c') > 1200000: out['issues'].append({'severity':'critical','title':'Слишком большой p2c','meaning':'Параметр p2c выглядит опасно большим и может вызвать нагрузку на CPU.'})
    if zipv: out['issues'].append({'severity':'high','title':f'Включено сжатие zip={zipv}','meaning':'Сжатие в JWE повышает риск decompression-bomb и побочных каналов.'})
    if enc in ('A128CBC-HS256','A192CBC-HS384','A256CBC-HS512'): out['issues'].append({'severity':'medium','title':'Используется CBC-HMAC','meaning':'Нужно внимательно смотреть обработку ошибок, чтобы не было oracle-поведения.'})
    if enc in ('A128GCM','A192GCM','A256GCM'): out['notes'].append('AEAD-режим сам по себе лучше, но всё равно нужно смотреть реализацию nonce/IV.')
    out['score'] = min(sum(sev_score(i['severity']) for i in out['issues']), 100)
    out['summary'] = 'Это пассивная оценка JWE-рисков по заголовку.'
    out['next_steps'] = ['Если это твой тестовый стенд, проверь реакцию сервера на изменённые JWE только в контролируемой среде.', 'Сначала смотри alg, enc, p2c, zip и наличие epk/kid/jku/x5u.']
    return out

def oidc_hints(token, profile=None):
    parts = token.split('.')
    out = {'mode':'OIDC CONFUSION HINTS','kind': token_kind(token), 'issues': [], 'notes': [], 'next_steps': []}
    if out['kind'] != 'JWS':
        out['issues'].append({'severity':'info','title':'Это не JWS/JWT','meaning':'OIDC hints работают для обычных JWT из 3 частей.'})
        out['score']=0; out['summary']='Передан не JWS-токен.'; return out
    header = safe_b64json(parts[0]); payload = safe_b64json(parts[1])
    out['header'] = header; out['payload'] = payload
    typ = header.get('typ') if isinstance(header, dict) else None
    if typ not in ('at+jwt','application/at+jwt'):
        out['issues'].append({'severity':'medium','title':'typ не похож на access token','meaning':'Для access token в OAuth/OIDC часто ожидается at+jwt или application/at+jwt.'})
    if isinstance(payload, dict):
        if 'nonce' in payload:
            out['notes'].append('Есть nonce: это сильный признак ID Token.')
        if 'azp' in payload or 'scope' in payload or 'client_id' in payload:
            out['notes'].append('Есть признаки access token / OAuth-контекста.')
        if 'aud' not in payload:
            out['issues'].append({'severity':'high','title':'Нет aud','meaning':'Без aud проще допустить cross-service relay или приём токена не тем сервисом.'})
        if 'iss' not in payload:
            out['issues'].append({'severity':'high','title':'Нет iss','meaning':'Без iss сложнее корректно отделять токены разных issuer/realm.'})
        if profile and profile.get('expect_access_token') and 'nonce' in payload:
            out['issues'].append({'severity':'high','title':'Похоже на ID Token вместо access token','meaning':'Профиль ожидает access token, но nonce характерен для ID Token.'})
            out['next_steps'].append('Проверь, не принимает ли API OIDC ID Token там, где должен приниматься только access token.')
    out['score'] = min(sum(sev_score(i['severity']) for i in out['issues']), 100)
    out['summary'] = 'Проверка помогает понять, не перепутан ли тип токена в OAuth/OIDC.'
    if not out['next_steps']:
        out['next_steps'].append('Если у тебя есть профиль API, повтори команду с --profile.')
    return out

def psychic_indicator(token):
    parts = token.split('.')
    out = {'mode':'PSYCHIC SIGNATURE INDICATOR','kind': token_kind(token), 'issues': [], 'notes': [], 'next_steps': []}
    if out['kind'] != 'JWS':
        out['issues'].append({'severity':'info','title':'Это не JWS/JWT','meaning':'Проверка имеет смысл только для ES256/384/512 JWT.'})
        out['score']=0; out['summary']='Передан не JWS-токен.'; return out
    header = safe_b64json(parts[0])
    if not isinstance(header, dict):
        out['issues'].append({'severity':'high','title':'Header не декодируется','meaning':'Нельзя понять алгоритм токена.'})
        out['score']=20; out['summary']='Нельзя корректно прочитать header.'; return out
    alg = str(header.get('alg','')); sizes = {'ES256':64,'ES384':96,'ES512':132}
    if alg not in sizes:
        out['issues'].append({'severity':'info','title':'Токен не ES256/ES384/ES512','meaning':'Индикатор Psychic Signatures относится к ECDSA JWT.'})
        out['score']=0; out['summary']='Алгоритм токена не подходит под эту проверку.'; return out
    zero_sig = base64.urlsafe_b64encode(b'\x00' * sizes[alg]).rstrip(b'=').decode()
    out['candidate'] = parts[0] + '.' + parts[1] + '.' + zero_sig
    out['issues'].append({'severity':'high','title':'Сгенерирован zero-signature кандидат','meaning':'Если уязвимая Java ECDSA-проверка примет такой токен, это признак старой уязвимости CVE-2022-21449 в контролируемой среде.'})
    out['notes'].append('Это не “эксплойт-кнопка”, а регрессионный тест для своей лаборатории.')
    out['next_steps'].append('Возьми поле candidate и проверь его только на своём стенде или в разрешённой тестовой среде.')
    out['next_steps'].append('Если сервер на Java 15–18 и использует уязвимую ECDSA-проверку, такой токен может быть принят.')
    out['score'] = 20
    out['summary'] = 'Построен тестовый токен для проверки исторической ECDSA-ошибки в Java.'
    return out

def pretty_print(data):
    print('\n' + '='*72)
    print(data.get('mode', 'RESULT'))
    print('='*72)
    print(f"Итог: {data.get('summary','-')}")
    print(f"Тип токена: {data.get('kind','-')}")
    print(f"Оценка риска: {data.get('score',0)}/100")
    print()
    if data.get('issues'):
        print('Что найдено:')
        for i, issue in enumerate(data['issues'], 1):
            print(f"  {i}. [{SEV_TEXT.get(issue['severity'], issue['severity'])}] {issue['title']}")
            if issue.get('meaning'):
                print(f"     Что это значит: {issue['meaning']}")
            if issue.get('value') is not None:
                print(f"     Значение: {issue['value']}")
    else:
        print('Что найдено: серьёзных проблем не обнаружено.')
    if data.get('notes'):
        print('\nДополнительно:')
        for n in data['notes']:
            print(f'  - {n}')
    if data.get('candidate'):
        print('\nСгенерированный тестовый токен:')
        print(data['candidate'])
    if data.get('next_steps'):
        print('\nЧто делать дальше:')
        for step in data['next_steps']:
            print(f'  - {step}')
    if data.get('reports'):
        print('\nФайлы отчёта:')
        print(f"  - JSON: {data['reports']['json']}")
        print(f"  - HTML: {data['reports']['html']}")
    print('\n--- RAW JSON ---')
    print(json.dumps(data, ensure_ascii=False, indent=2))

HELP_TEXT = '''
JWT Tool Enhanced — дружелюбная обёртка над jwt_tool

Зачем это нужно:
  Эта утилита помогает быстро понять, что означает токен и куда смотреть дальше.
  Она не только печатает JSON, но и объясняет вывод простыми словами.

Основные режимы:
  1) --rfc8725-audit <token>
     Когда использовать: у тебя есть обычный JWT и ты хочешь понять,
     нет ли опасных признаков в духе RFC 8725: alg=none, странный kid,
     отсутствие exp/iss/aud, подозрительные JOSE-заголовки.

  2) --oidc-hints <token>
     Когда использовать: токен пришёл из OAuth/OIDC, и ты хочешь понять,
     не перепутали ли ID Token и Access Token.

  3) --jwe-audit <token>
     Когда использовать: токен состоит из 5 частей, и ты хочешь быстро понять,
     какие JWE-риски видны по заголовку.

  4) --psychic-indicator <token>
     Когда использовать: токен подписан ES256/384/512 и ты хочешь получить
     тестовый zero-signature кандидат для своего стенда Java.

Дополнительные флаги:
  --profile <file>       профиль сервиса в YAML/JSON
  --report-base <name>   сохранить HTML и JSON отчёт в папку reports/
  --delegate ...         передать остальные аргументы в оригинальный jwt_tool.py

Примеры:
  python3 jwt_tool_enhanced.py --rfc8725-audit '<JWT>'
  python3 jwt_tool_enhanced.py --oidc-hints '<JWT>' --profile profiles/api-access-token.yaml
  python3 jwt_tool_enhanced.py --jwe-audit '<JWE>' --report-base jwe_test
  python3 jwt_tool_enhanced.py --psychic-indicator '<ES256 JWT>'
  python3 jwt_tool_enhanced.py --delegate --help

Совет:
  Если не знаешь, с чего начать, почти всегда начни с --rfc8725-audit.
'''

def main():
    if '-h' in sys.argv or '--help' in sys.argv or len(sys.argv) == 1:
        print(HELP_TEXT)
        return
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument('--rfc8725-audit')
    ap.add_argument('--jwe-audit')
    ap.add_argument('--oidc-hints')
    ap.add_argument('--psychic-indicator')
    ap.add_argument('--profile')
    ap.add_argument('--report-base')
    ap.add_argument('--delegate', nargs=argparse.REMAINDER)
    args = ap.parse_args()
    prof = load_profile(args.profile) if args.profile else None
    data = None
    if args.rfc8725_audit:
        data = rfc8725_audit(args.rfc8725_audit, prof)
    elif args.jwe_audit:
        data = jwe_audit(args.jwe_audit)
    elif args.oidc_hints:
        data = oidc_hints(args.oidc_hints, prof)
    elif args.psychic_indicator:
        data = psychic_indicator(args.psychic_indicator)
    elif args.delegate is not None:
        os.execv(sys.executable, [sys.executable, 'jwt_tool.py'] + args.delegate)
    else:
        print(HELP_TEXT)
        return
    if args.report_base:
        data['reports'] = save_report(args.report_base, data)
    pretty_print(data)

if __name__ == '__main__':
    main()
