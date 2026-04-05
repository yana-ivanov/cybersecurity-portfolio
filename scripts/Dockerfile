FROM python:3.12-slim

WORKDIR /app

COPY waveshaper_triage.py .
COPY waveshaper_server.py .

RUN pip install flask --quiet

EXPOSE 5000

CMD ["python3", "waveshaper_server.py"]
