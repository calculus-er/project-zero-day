Drop one ``*.py`` here (any filename).

- Host: ``python scripts/sync_incoming_to_app.py`` copies it onto ``../source/app.py``.
- Docker: set ``ARENA_INCOMING_SYNC=true`` (e.g. in ``.env`` for compose); the target
  entrypoint copies ``/incoming/*.py`` to ``/app/app.py`` before Flask starts.

If several ``*.py`` files exist here, set ``ARENA_INCOMING_FILE=yourfile.py``.
