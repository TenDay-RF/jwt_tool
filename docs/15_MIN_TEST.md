# Сценарий тестирования на 15 минут

## 1. Проверить help
```bash
python3 jwt_tool_enhanced.py -h
```
Ожидаемо: увидишь человеческое объяснение режимов и примеры запуска.

## 2. Проверить alg=none
```bash
python3 jwt_tool_enhanced.py --rfc8725-audit 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.'
```
Ожидаемо: будет написано по-русски, что токен неподписанный и что делать дальше.

## 3. Проверить suspicious kid
```bash
python3 jwt_tool_enhanced.py --rfc8725-audit 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii4uLy4uL2V0Yy9wYXNzd2QifQ.eyJzdWIiOiIxIiwiaXNzIjoiaW50ZXJuYWwiLCJhdWQiOiJhcGkiLCJleHAiOjE5OTk5OTk5OTl9.c2ln'
```
Ожидаемо: будет сказано, что `kid` похож на path traversal / небезопасный lookup ключа.

## 4. Проверить OIDC confusion
```bash
python3 jwt_tool_enhanced.py --oidc-hints 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsImF1ZCI6Im15LWNsaWVudC1pZCIsIm5vbmNlIjoiYWJjMTIzIiwiZXhwIjoxOTk5OTk5OTk5fQ.c2ln' --profile profiles/api-access-token.yaml
```
Ожидаемо: будет сказано, что профиль ждёт access token, а токен больше похож на ID Token.

## 5. Проверить JWE audit
```bash
python3 jwt_tool_enhanced.py --jwe-audit 'eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIiwicDJjIjoyMDAwMDAwfQ.ZW5jcnlwdGVka2V5.aXY.Y2lwaGVydGV4dA.dGFn'
```
Ожидаемо: будут подсвечены RSA1_5, zip, p2c и CBC-HMAC.

## 6. Проверить Psychic Signatures indicator
```bash
python3 jwt_tool_enhanced.py --psychic-indicator 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImV4cCI6MTk5OTk5OTk5OX0.c2ln'
```
Ожидаемо: увидишь понятное объяснение, что это тестовый zero-signature кандидат для своего стенда.

## 7. Поднять локальный стенд
```bash
cd docker-lab
docker compose up --build
```
Потом в другом окне:
```bash
curl http://127.0.0.1:8087/issue/unsafe-none-admin
curl http://127.0.0.1:8087/issue/unsafe-kid-admin
curl http://127.0.0.1:8087/issue/id-token
```
