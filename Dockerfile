FROM python:3.9-slim

# Устанавливаем зависимости
RUN apt-get update && apt-get install -y \
    ipset \
    iptables \
    nftables \
    rsyslog \
    && rm -rf /var/lib/apt/lists/*

# Устанавливаем Python-зависимости
RUN pip install flask

# Создаём рабочую директорию
WORKDIR /app

# Копируем код
COPY app.py initialize_iptables.py collect_stats.py db.py /app/
COPY templates/ /app/templates/

# Настраиваем rsyslog для логов iptables
COPY rsyslog.conf /etc/rsyslog.d/iptables.conf

# Открываем порт для Flask
EXPOSE 5000

CMD ["python", "app.py"]
