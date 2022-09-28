FROM python:3.10

USER root
COPY vscn_loader/ vscn_loader/
COPY scripts/ scripts/
COPY requirements.txt .
COPY .env .env
RUN apt-get update && apt-get -y install jq
RUN chmod +x scripts/extract-cve.sh
RUN chmod +x scripts/extract-matchers.sh
ENV PYTHONPATH="/"
RUN pip install -r requirements.txt
CMD ["python", "vscn_loader/main.py"]