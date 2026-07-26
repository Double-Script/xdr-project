FROM python:3.12-slim

WORKDIR /project

COPY app/requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONPATH=/project

WORKDIR /project/app

EXPOSE 5000

CMD ["python", "app.py"]