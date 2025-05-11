from flask import Flask, request, jsonify, render_template
import sqlite3
import time
import datetime

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect('/app/filter.db')
    conn.execute('''CREATE TABLE IF NOT EXISTS stats (
        timestamp INTEGER,
        interface TEXT,
        total INTEGER,
        passed INTEGER,
        dropped INTEGER
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS interfaces (
        name TEXT PRIMARY KEY,
        type TEXT
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS monitoring_objects (
        name TEXT PRIMARY KEY,
        interfaces TEXT,
        ips TEXT,
        threshold INTEGER,
        filter_active BOOLEAN DEFAULT 0,
        template TEXT
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS countermeasures (
        ip TEXT PRIMARY KEY,
        type TEXT
    )''')
    conn.commit()
    conn.close()

def get_db_connection():
    conn = sqlite3.connect('/app/filter.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/interfaces', methods=['GET'])
def get_interfaces():
    conn = get_db_connection()
    interfaces = conn.execute('SELECT DISTINCT interface FROM stats WHERE interface IS NOT NULL').fetchall()
    conn.close()
    return jsonify([row['interface'] for row in interfaces if row['interface']])

@app.route('/api/set_interface_type', methods=['POST'])
def set_interface_type():
    data = request.get_json()
    interface = data.get('interface')
    interface_type = data.get('type')
    if not interface or not interface_type:
        return jsonify({'status': 'error', 'message': 'Missing interface or type'}), 400
    conn = get_db_connection()
    conn.execute('INSERT OR REPLACE INTO interfaces (name, type) VALUES (?, ?)', (interface, interface_type))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success', 'message': f'Interface {interface} set to {interface_type}'})

@app.route('/api/create_monitoring', methods=['GET', 'POST'])
def create_monitoring():
    conn = get_db_connection()
    if request.method == 'POST':
        data = request.get_json()
        name = data.get('name')
        interfaces = data.get('interfaces', [])
        ips = data.get('ips', [])
        threshold = data.get('threshold')
        template = data.get('template')
        if not name or not interfaces or not threshold:
            conn.close()
            return jsonify({'status': 'error', 'message': 'Missing required fields'}), 400
        conn.execute('INSERT INTO monitoring_objects (name, interfaces, ips, threshold, template) VALUES (?, ?, ?, ?, ?)',
                     (name, ','.join(interfaces), ','.join(ips), threshold, template))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'message': f'Monitoring object {name} created'})
    else:
        objects = conn.execute('SELECT * FROM monitoring_objects').fetchall()
        conn.close()
        return jsonify([dict(row) for row in objects])

@app.route('/api/set_threshold', methods=['POST'])
def set_threshold():
    data = request.get_json()
    name = data.get('name')
    threshold = data.get('threshold')
    if not name or not threshold:
        return jsonify({'status': 'error', 'message': 'Missing name or threshold'}), 400
    conn = get_db_connection()
    conn.execute('UPDATE monitoring_objects SET threshold = ? WHERE name = ?', (threshold, name))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success', 'message': f'Threshold for {name} updated to {threshold}'})

@app.route('/api/set_countermeasure', methods=['POST'])
def set_countermeasure():
    data = request.get_json()
    ip = data.get('ip')
    counter_type = data.get('type')
    if not ip or not counter_type:
        return jsonify({'status': 'error', 'message': 'Missing IP or type'}), 400
    conn = get_db_connection()
    conn.execute('INSERT INTO countermeasures (ip, type) VALUES (?, ?)', (ip, counter_type))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success', 'message': f'Countermeasure added: {ip} ({counter_type})'})

@app.route('/api/remove_countermeasure', methods=['POST'])
def remove_countermeasure():
    data = request.get_json()
    ip = data.get('ip')
    if not ip:
        return jsonify({'status': 'error', 'message': 'Missing IP'}), 400
    conn = get_db_connection()
    conn.execute('DELETE FROM countermeasures WHERE ip = ?', (ip,))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success', 'message': f'Countermeasure removed: {ip}'})

@app.route('/api/get_stats', methods=['GET'])
def get_stats():
    range = request.args.get('range', '5m')
    time_ranges = {
        '5m': 5 * 60,
        '30m': 30 * 60,
        '1h': 60 * 60,
        '3h': 3 * 60 * 60,
        '24h': 24 * 60 * 60
    }
    time_delta = time_ranges.get(range, 5 * 60)
    since = int(time.time()) - time_delta
    conn = get_db_connection()
    stats = conn.execute('SELECT * FROM stats WHERE timestamp >= ?', (since,)).fetchall()
    
    # Получаем все типы контрмер из таблицы countermeasures
    counter_types = conn.execute('SELECT DISTINCT type FROM countermeasures').fetchall()
    counter_types = [row['type'] for row in counter_types]

    # Формируем статистику
    result = []
    for stat in stats:
        stat_dict = dict(stat)
        # Инициализируем словарь для трафика по контрмерам
        stat_dict['countermeasures'] = {}
        for counter_type in counter_types:
            # Здесь мы пока не можем взять данные из stats, так как столбцы для контрмер не добавлены
            # В будущем нужно будет модифицировать filter.go/traffic.go для записи таких данных
            stat_dict['countermeasures'][counter_type] = 0
        result.append(stat_dict)
    
    conn.close()
    return jsonify(result)

@app.route('/api/overview', methods=['GET'])
def overview():
    conn = get_db_connection()
    monitoring_objects = conn.execute('SELECT * FROM monitoring_objects').fetchall()
    interfaces = conn.execute('SELECT * FROM interfaces').fetchall()
    conn.close()
    return jsonify({
        'monitoring_objects': [dict(row) for row in monitoring_objects],
        'interfaces': [dict(row) for row in interfaces]
    })

if __name__ == '__main__':
    init_db()  # Инициализируем базу данных при старте
    app.run(host='0.0.0.0', port=5000)
