FROM python:3.10-slim
WORKDIR /app
# install ping
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping && rm -rf /var/lib/apt/lists/*
# copy shared module
COPY shared /app/shared
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
COPY init_db.py .
EXPOSE 5000
CMD ["python", "app.py"]
