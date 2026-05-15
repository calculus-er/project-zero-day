FROM python:3.11-slim

WORKDIR /app

# Dependencies baked into image; application code comes from the host mount
# (see docker-compose: ./arena/source -> /app).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5000

CMD ["python", "app.py"]
