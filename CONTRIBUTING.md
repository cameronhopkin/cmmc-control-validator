# Contributing to CMMC Control Validator

Thank you for your interest in contributing to CMMC Control Validator! This document provides guidelines for contributing to the project.

## Code of Conduct

Please be respectful and constructive in all interactions. We're all here to build better security tools.

## How to Contribute

### Reporting Issues

1. Check existing issues to avoid duplicates
2. Use the issue template when available
3. Include:
   - Python version
   - Operating system
   - Steps to reproduce
   - Expected vs actual behavior
   - Relevant log output

### Submitting Changes

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass: `pytest`
6. Run linting: `ruff check .` and `black --check .`
7. Commit with clear messages
8. Push and create a Pull Request

### Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/cmmc-control-validator.git
cd cmmc-control-validator

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install in development mode
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=cmmc_validator --cov-report=html

# Run specific test file
pytest tests/test_terraform_parser.py

# Run specific test
pytest tests/test_terraform_parser.py::test_parse_s3_bucket
```

### Code Style

We use:
- **Black** for code formatting
- **isort** for import sorting
- **Ruff** for linting
- **mypy** for type checking

```bash
# Format code
black src/ tests/
isort src/ tests/

# Check linting
ruff check src/ tests/

# Type checking
mypy src/
```

### Adding New Controls

1. Add control definition to `src/cmmc_validator/controls/`
2. Add check implementation to `src/cmmc_validator/checks/`
3. Update resource mapping in `src/cmmc_validator/data/control_to_aws_mapping.json`
4. Add tests in `tests/`
5. Update documentation

### Adding New Resource Types

1. Update `TerraformParser` if needed
2. Add resource checks in appropriate check module
3. Update `control_to_aws_mapping.json`
4. Add test cases

## Pull Request Guidelines

- Keep PRs focused on a single change
- Include tests for new functionality
- Update documentation as needed
- Ensure CI passes
- Request review from maintainers

## Questions?

Open an issue with the "question" label or reach out to the maintainers.

Thank you for contributing!
