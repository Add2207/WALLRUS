# Contributing to WALLRUS

First off, thanks for taking the time to contribute! 🦦

## How Can I Contribute?

### Reporting Bugs
- Use GitHub Issues
- Include WALLRUS version, OS, Python version
- Provide sample HTTP request that triggered the bug
- Include error messages and stack traces

### Suggesting Features
- Open a GitHub Issue with `[Feature Request]` prefix
- Explain the use case and benefit
- Provide examples if possible

### Adding Detection Rules
New OWASP signatures are always welcome!

1. Add to `src/wallrus/core/signatures.py`
2. Follow the existing pattern:
```python
_rule(
    "ATTACK-XXX",           # Unique ID
    "Attack Name",          # Human-readable
    "A0X:2021 - Category",  # OWASP mapping
    Severity.HIGH,          # CRITICAL/HIGH/MEDIUM/LOW
    r"regex pattern here",  # The detection pattern
    [Target.QUERY],         # Where to scan
    "What this catches"     # Description
)
```
3. Add test cases in `tests/test_core/test_engine.py`
4. Run tests: `pytest tests/ -v`

### Code Style
- Follow PEP 8
- Use type hints where possible
- Add docstrings for new functions
- Run `ruff` before committing

### Pull Request Process

1. Fork the repo
2. Create your feature branch: `git checkout -b feature/AmazingFeature`
3. Commit your changes: `git commit -m 'Add some AmazingFeature'`
4. Push to the branch: `git push origin feature/AmazingFeature`
5. Open a Pull Request

### Development Setup

```bash
git clone https://github.com/Add2207/WALLRUS.git
cd WALLRUS
python3 -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
pytest tests/ -v
```

## Phase 2 ML Contributions

If you want to help with Phase 2 anomaly detection:
- See `scripts/train.py` for training pipeline
- Check `src/wallrus/ml/detector.py` for feature engineering
- Labelled datasets welcome (with proper licensing)

## Code of Conduct

Be respectful. We're all here to learn and improve security together.

## Questions?

Open a GitHub Discussion or Issue. We're happy to help!
