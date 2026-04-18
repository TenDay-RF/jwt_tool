# JWT Toolkit v2

> `jwt_tool_enhanced.py` is a Python toolkit for validating, analyzing, tampering with, and testing JSON Web Tokens (JWTs) in controlled security assessments.

![version](https://img.shields.io/badge/version-v2.3.0-blue) ![python](https://img.shields.io/badge/python-v3.6+-green)

`jwt_tool_enhanced.py` is designed for security testing of JWT-based authentication systems. It helps inspect token structure, identify risky header and claim patterns, test for common misconfigurations, and support controlled verification workflows for security research and CTF practice.

Its functionality includes:
* Checking the validity of a token.
* Inspecting JWT header and payload values.
* Testing for known weaknesses and historical JWT issues.
* Scanning for misconfigurations and risky token handling behavior.
* Fuzzing claims to observe unexpected application responses.
* Testing secret files, public keys, and JWKS data.
* Identifying weak signing keys via dictionary-based checks.
* Forging modified token contents and rebuilding signatures when a valid key is available.
* Timestamp and claim tampering for controlled validation testing.
* RSA and ECDSA key generation and JWKS-based reconstruction.
* Rate limiting for attack routines.
* ...and more.

## Audience

This tool is intended for:
* **Pentesters** who assess JWT implementations in real applications.
* **CTF players** who work on JWT-related challenges.
* **Developers** who want to verify how their JWT handling behaves under malformed or modified inputs.

## Requirements

This tool is written in **Python 3.6+** and uses common Python libraries for token processing and cryptographic operations.

## Installation

### Docker
If you use Docker, run the tool with the provided image and mount your working directory and config directory as needed.

### Manual install
```bash
git clone https://github.com/TenDay-RF/jwt_tool.git
python3 -m pip install -r requirements.txt
```

## Usage

Run the tool against a JWT to decode and inspect its contents:

```bash
python3 jwt_tool_enhanced.py <JWT>
```

Display help:

```bash
python3 jwt_tool_enhanced.py -h
```

## Examples

```bash
python3 jwt_tool_enhanced.py --delegate <JWT>
```
```bash
python3 jwt_tool_enhanced.py --rfc8725-audit '<JWT>'
```
```bash
python3 jwt_tool_enhanced.py --oidc-hints '<JWT>' --profile profiles/api-access-token.yaml
```
```bash
python3 jwt_tool_enhanced.py --jwe-audit '<JWE>' --report-base jwe_test
```
```bash
python3 jwt_tool_enhanced.py --psychic-indicator '<ES256 JWT>'
```
## Notes

The tool is intended for authorized security testing, research, and controlled practice only.
