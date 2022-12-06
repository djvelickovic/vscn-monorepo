FROM python:3.10

COPY vscn_server/ vscn_server/
COPY requirements.txt .
COPY products-set.json ./products-set.json
COPY .env .env
RUN pip install -r requirements.txt
CMD ["gunicorn", "-w", "4", "vscn_server.app:app", "-b", "0.0.0.0:80"]