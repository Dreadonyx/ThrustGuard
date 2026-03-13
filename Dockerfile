# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy the requirements file into the container
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code into the container
COPY . .

# Expose port 8000 for the FastAPI service
EXPOSE 8000

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV ECLIPSE_API_HOST=0.0.0.0
ENV OLLAMA_HOST=http://host.docker.internal:11434

# Run main.py when the container launches
CMD ["python", "main.py"]
