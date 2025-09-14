FROM python:3.12-slim

WORKDIR /app

COPY check.py . 

CMD ["python3", "check.py"]
