FROM python:3.12-slim

WORKDIR /app

COPY certs ./certs
COPY server ./server

ENV PYTHONUNBUFFERED=1
ENV MTLS_SERVER_HOST=0.0.0.0
ENV MTLS_SERVER_PORT=8443

EXPOSE 8443

CMD ["python", "server/server.py"]
