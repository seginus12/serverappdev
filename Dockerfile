FROM python:3.13.0a4-slim

WORKDIR /app

RUN apt update && apt upgrade
RUN apt install -y build-essential libssl-dev libffi-dev python3-dev
RUN pip install --upgrade pip

COPY requirements.txt .
RUN cat requirements.txt
RUN pip install -r requirements.txt

COPY . .
