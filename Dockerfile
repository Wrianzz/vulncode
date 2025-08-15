# Gunakan base image Python resmi
FROM python:3.10-slim

# Set working directory di dalam container
WORKDIR /app

# Salin requirements.txt terlebih dahulu
COPY requirements.txt .
COPY app.py .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose port 8000 untuk Flask
EXPOSE 8000

# Jalankan aplikasi Flask
CMD ["python", "app.py"]
