FROM python:3.12-slim

WORKDIR /app

RUN apt update && apt upgrade -y
RUN apt install -y build-essential libssl-dev libffi-dev python3-dev
RUN pip install --upgrade pip

COPY requirements.txt .
RUN cat requirements.txt
RUN pip install -r requirements.txt

COPY . .
