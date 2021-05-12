FROM python:3.8-slim

RUN python3.8 -m venv /usr/share/python3/app && \
/usr/share/python3/app/bin/pip install -U pip

WORKDIR /usr/src/app

COPY requirements.txt requirements.txt
RUN python -m pip install -r requirements.txt

COPY  . .