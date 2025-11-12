"""
Gevent monkey patching - MUST be imported first before any other modules.

This patches Python's standard library to use gevent's cooperative greenlets,
enabling high concurrency with Gunicorn's gevent worker class.
"""

from gevent import monkey  # type: ignore

# Patch all standard library modules before they are imported
monkey.patch_all()
