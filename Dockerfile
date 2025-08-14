# Gunakan base image Python resmi
FROM python:3.10-slim

# Buat user non-root 'test' dan group 'test'
RUN addgroup --system test && adduser --system --ingroup test test

# Set working directory
WORKDIR /app

# Salin requirements.txt terlebih dahulu
COPY requirements.txt .

# Install dependencies (pakai root)
RUN pip install --no-cache-dir -r requirements.txt

# Salin semua file aplikasi
COPY . .

# Ubah kepemilikan folder /app ke user test
RUN chown -R test:test /app

# Pindah ke user non-root
USER test

# Expose port untuk Flask
EXPOSE 8000

# Jalankan aplikasi Flask
CMD ["python", "app.py"]
