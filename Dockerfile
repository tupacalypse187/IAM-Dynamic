FROM python:3.11-slim

WORKDIR /app

# Install only if you actually need system packages (uncomment if adding them)
# RUN apt-get update && apt-get install -y --no-install-recommends \
#     build-essential \
#  && rm -rf /var/lib/apt/lists/*

# Upgrade pip, install Python dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -r requirements.txt

# Copy all application files
COPY . .

EXPOSE 8501

CMD ["streamlit", "run", "dynamicIAM_web.py", "--server.address=0.0.0.0", "--server.port=8501"]
