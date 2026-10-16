FROM python:3.12-slim
WORKDIR /app
COPY app.py import_putintei.py start.py ./
COPY import_data ./import_data
ENV PYTHONUNBUFFERED=1 PORT=8000 DB_PATH=/data/geopajisti.sqlite3 COOKIE_SECURE=1
RUN mkdir -p /data
EXPOSE 8000
CMD ["python", "start.py"]
