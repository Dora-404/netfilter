from flask import Flask, render_template, request, redirect, url_for, jsonify
import logging
import subprocess
from db import get_db, init_db
from initialize_iptables import initialize_iptables

app = Flask(__name__)

# Настройка логирования
logging.basicConfig(
    filename="/app/data/traffic_filter.log",
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger()

# Добавляем консольный вывод
console = logging.StreamHandler()
console.setLevel(logging.DEBUG)
console.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(console)

@app.route("/")
def index():
    """Главная страница: список ресурсов."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, ip, ports, chain FROM resources")
        resources = [dict(row) for row in cursor.fetchall()]
    return render_template("index.html", resources=resources)

@app.route("/add_resource", methods=["GET", "POST"])
def add_resource():
    """Добавление нового ресурса."""
    if request.method == "POST":
        name = request.form["name"]
        ip = request.form["ip"]
        ports = request.form.get("ports", "")
        chain = f"{name.upper().replace(' ', '_')}_FILTER"
        
        logger.info(f"Adding resource: {name} ({ip}, ports: {ports}, chain: {chain})")
        
        with get_db() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "INSERT INTO resources (name, ip, ports, chain) VALUES (?, ?, ?, ?)",
                    (name, ip, ports, chain)
                )
                conn.commit()
                logger.info("Resource added to database")
                
                # Перегенерируем правила
                initialize_iptables()
            except Exception as e:
                logger.error(f"Failed to add resource: {e}")
                conn.rollback()
        
        return redirect(url_for("index"))
    
    return render_template("add_resource.html")

@app.route("/resource/<int:resource_id>", methods=["GET", "POST"])
def manage_resource(resource_id):
    """Управление списками WL, BL, TBL для ресурса."""
    with get_db() as conn:
        cursor = conn.cursor()
        
        if request.method == "POST":
            list_type = request.form["list_type"]
            ip = request.form["ip"]
            
            logger.info(f"Adding IP {ip} to {list_type} for resource {resource_id}")
            
            try:
                cursor.execute(
                    "INSERT INTO lists (resource_id, list_type, ip) VALUES (?, ?, ?)",
                    (resource_id, list_type, ip)
                )
                cursor.execute("SELECT chain FROM resources WHERE id = ?", (resource_id,))
                chain = cursor.fetchone()[0]
                
                # Добавляем IP в nftables set
                subprocess.run(
                    f"nft add element ip {list_type}_{chain.lower()} {{ {ip} }}",
                    shell=True,
                    check=True
                )
                conn.commit()
                logger.info(f"IP {ip} added to {list_type}_{chain.lower()}")
            except Exception as e:
                logger.error(f"Failed to add IP: {e}")
                conn.rollback()
        
        # Изменяем запрос, добавляя id
        cursor.execute("SELECT id, name, ip, ports, chain FROM resources WHERE id = ?", (resource_id,))
        resource = cursor.fetchone()
        cursor.execute("SELECT id, list_type, ip FROM lists WHERE resource_id = ?", (resource_id,))
        lists = cursor.fetchall()
        
        # Преобразуем resource и lists в словари
        resource_dict = dict(resource) if resource else None
        lists_dict = [dict(row) for row in lists]
    
    return render_template("manage_resource.html", resource=resource_dict, lists=lists_dict)

@app.route("/edit_resource/<int:resource_id>", methods=["GET", "POST"])
def edit_resource(resource_id):
    """Редактирование ресурса."""
    with get_db() as conn:
        cursor = conn.cursor()
        
        if request.method == "POST":
            name = request.form["name"]
            ip = request.form["ip"]
            ports = request.form.get("ports", "")
            chain = f"{name.upper().replace(' ', '_')}_FILTER"
            
            logger.info(f"Editing resource {resource_id}: {name} ({ip}, ports: {ports}, chain: {chain})")
            
            try:
                cursor.execute(
                    "UPDATE resources SET name = ?, ip = ?, ports = ?, chain = ? WHERE id = ?",
                    (name, ip, ports, chain, resource_id)
                )
                conn.commit()
                logger.info("Resource updated in database")
                
                # Перегенерируем правила
                initialize_iptables()
            except Exception as e:
                logger.error(f"Failed to update resource: {e}")
                conn.rollback()
            
            return redirect(url_for("manage_resource", resource_id=resource_id))
        
        cursor.execute("SELECT id, name, ip, ports, chain FROM resources WHERE id = ?", (resource_id,))
        resource = cursor.fetchone()
        resource_dict = dict(resource) if resource else None
    
    return render_template("edit_resource.html", resource=resource_dict)

@app.route("/traffic_stats/<int:resource_id>")
def traffic_stats(resource_id):
    """API для получения статистики трафика."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT timestamp, rule, packets, bytes FROM traffic_stats WHERE resource_id = ? ORDER BY timestamp",
            (resource_id,)
        )
        stats = [dict(row) for row in cursor.fetchall()]
    return jsonify(stats)

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
