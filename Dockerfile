FROM python:3.12-alpine

# Create non-root user
RUN adduser -h /opt/app -D -u 5000 www

# Install dependencies
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && rm -f /tmp/requirements.txt

# Copy sources
COPY *.py /opt/app
COPY templates /opt/app/templates
COPY static /opt/app/static

# Expose port
EXPOSE 5000

# Entrypoint
USER www
WORKDIR /opt/app
CMD ["flask", "--app", "app.py", "--debug", "run", "-h", "0.0.0.0", "-p", "5000"]