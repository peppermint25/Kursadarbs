FROM python:latest

# Set working directory
WORKDIR /backend

# Copy requirements.txt to the working directory
COPY requirements.txt requirements.txt

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire application to the container
COPY ./uploads /app/uploads/
COPY ./images /app/images/

# Expose port 5000 for Flask
EXPOSE 5000

# Run the application
CMD ["python", "-m", "flask", "run", "--host=0.0.0.0", "--port=5000"]