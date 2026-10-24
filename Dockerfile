FROM python:3.12-slim
# docker CLI so the execution engine can launch sandboxed tool containers
RUN apt-get update && apt-get install -y --no-install-recommends docker.io curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
