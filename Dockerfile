FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY . /app
# Explicitly activate the Q3 overlay; Q1/Q2 source remains unchanged.
RUN sed -i 's/^import q3_invoice_agent$/import q3_invoice_agent_v2 as q3_invoice_agent/' /app/server.py
ENV PORT=10000
EXPOSE 10000
CMD ["python", "/app/server.py"]
