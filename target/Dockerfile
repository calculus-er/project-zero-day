FROM python:3.11-slim

WORKDIR /app

# Dependencies baked into image; application code comes from the host mount
# (see docker-compose: ./arena/source -> /app).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY incoming_sync.py /incoming_sync.py
COPY entrypoint.py /entrypoint.py

EXPOSE 5000

ENV ARENA_ENTRY_FILE=app.py
CMD ["python", "/entrypoint.py"]
