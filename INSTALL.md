# Install

## Quick start
```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install termcolor cprint pycryptodomex requests ratelimit pytest pyyaml
python3 jwt_tool.py -h
python3 jwt_tool_enhanced.py -h
```

## Notes
- `jwt_tool.py -h` now shows an enhanced-help notice.
- `ratelimit` is optional in this packaged fork because a fallback import was added.
- YAML profiles require `pyyaml`; otherwise use JSON profile files.
