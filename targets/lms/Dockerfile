# Multi-arch base (works on x86 dev machine and ARM cloud VMs e.g. Oracle Ampere)
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

EXPOSE 5000

# Dev server is fine for a controlled test target.
CMD ["python", "app.py"]
