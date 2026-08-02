# Stage 1: Build Stage
FROM python:3.9-alpine

# Set the working directory in the container
WORKDIR /app

# Copy the application code
COPY . .

# Expose the port the application will run on
EXPOSE 8000

# Define the command to run the application
CMD ["python", "server.py"]
