# Configuration Files

This folder contains all configuration files for the GitHub Events Limiter application.

## Files

- **`config.py`** - Central Python configuration module with all application constants
- **`gunicorn.conf.py`** - Gunicorn web server configuration (workers, logging, lifecycle hooks)
- **`.flake8`** - Flake8 linter configuration
- **`.pylintrc`** - Pylint linter configuration

## Usage

These files are automatically imported by the application:
- `main.py` imports `config` module for application settings
- Gunicorn uses `gunicorn.conf.py` via the `-c` flag in the Dockerfile
- Linters use their respective config files automatically when run in the project directory
