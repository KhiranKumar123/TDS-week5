FROM python:3.12-slim
WORKDIR /app
COPY server.py /app/server.py
ENV PORT=10000
EXPOSE 10000
CMD ["python", "/app/server.py"]
