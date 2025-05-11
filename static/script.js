function showNotification(message, type) {
    const notification = document.getElementById('notification');
    notification.textContent = message;
    notification.className = `notification ${type}`;
    notification.style.display = 'block';
    notification.style.opacity = '1';
    setTimeout(() => {
        notification.style.opacity = '0';
        setTimeout(() => {
            notification.style.display = 'none';
        }, 500);
    }, 3000);
}

function openTab(tabName) {
    const tabs = document.getElementsByClassName('tabcontent');
    for (let i = 0; i < tabs.length; i++) {
        tabs[i].style.display = "none";
    }
    document.getElementById(tabName).style.display = "block";
    if (tabName === 'Overview') {
        loadOverview();
    }
}

function loadInterfaces() {
    fetch('/api/interfaces')
        .then(response => response.json())
        .then(interfaces => {
            const select = document.getElementById('interfaceList');
            const moSelect = document.getElementById('moInterfaces');
            select.innerHTML = '';
            moSelect.innerHTML = '';
            interfaces.forEach(iface => {
                const option = document.createElement('option');
                option.value = iface;
                option.textContent = iface;
                select.appendChild(option);
                const moOption = document.createElement('option');
                moOption.value = iface;
                moOption.textContent = iface;
                moSelect.appendChild(moOption);
            });
            console.log("Загружены интерфейсы:", interfaces);
        })
        .catch(error => {
            showNotification(`Failed to load interfaces: ${error}`, 'error');
            console.error("Ошибка загрузки интерфейсов:", error);
        });
}

function loadMonitoringObjects() {
    fetch('/api/create_monitoring')
        .then(response => response.json())
        .then(objects => {
            const thresholdSelect = document.getElementById('thresholdMO');
            const counterSelect = document.getElementById('counterMO');
            const chartSelect = document.getElementById('chartMO');
            thresholdSelect.innerHTML = '';
            counterSelect.innerHTML = '';
            chartSelect.innerHTML = '';
            objects.forEach(obj => {
                const option = document.createElement('option');
                option.value = obj.name;
                option.textContent = obj.name;
                thresholdSelect.appendChild(option);
                const counterOption = document.createElement('option');
                counterOption.value = obj.name;
                counterOption.textContent = obj.name;
                counterSelect.appendChild(counterOption);
                const chartOption = document.createElement('option');
                chartOption.value = obj.name;
                chartOption.textContent = obj.name;
                chartSelect.appendChild(chartOption);
            });
            console.log("Загружены объекты мониторинга:", objects);
        })
        .catch(error => {
            showNotification(`Failed to load monitoring objects: ${error}`, 'error');
            console.error("Ошибка загрузки объектов мониторинга:", error);
        });
}

function loadOverview() {
    fetch('/api/overview')
        .then(response => response.json())
        .then(data => {
            const monitoringTableBody = document.querySelector('#monitoringTable tbody');
            monitoringTableBody.innerHTML = '';
            data.monitoring_objects.forEach(obj => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${obj.name}</td>
                    <td>${obj.interfaces}</td>
                    <td>${obj.ips}</td>
                    <td>${obj.threshold}</td>
                    <td>${obj.filter_active ? 'Yes' : 'No'}</td>
                    <td>${obj.template || 'N/A'}</td>
                `;
                monitoringTableBody.appendChild(row);
            });

            const interfacesTableBody = document.querySelector('#interfacesTable tbody');
            interfacesTableBody.innerHTML = '';
            data.interfaces.forEach(iface => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${iface.name}</td>
                    <td>${iface.type || 'N/A'}</td>
                `;
                interfacesTableBody.appendChild(row);
            });
            console.log("Загружены данные для Overview:", data);
        })
        .catch(error => {
            showNotification(`Failed to load overview: ${error}`, 'error');
            console.error("Ошибка загрузки данных Overview:", error);
        });
}

function setInterfaceType() {
    const iface = document.getElementById('interfaceList').value;
    const type = document.getElementById('interfaceType').value;
    fetch('/api/set_interface_type', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ interface: iface, type: type })
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            showNotification(data.message, 'success');
        } else {
            showNotification(data.message, 'error');
        }
        console.log("Установка типа интерфейса:", data);
    })
    .catch(error => {
        showNotification(`Error: ${error}`, 'error');
        console.error("Ошибка установки типа интерфейса:", error);
    });
}

function createMonitoringObject() {
    const name = document.getElementById('moName').value;
    const interfaces = Array.from(document.getElementById('moInterfaces').selectedOptions).map(opt => opt.value);
    const ips = document.getElementById('moIPs').value.split(',').map(ip => ip.trim()).filter(ip => ip);
    const threshold = parseInt(document.getElementById('moThreshold').value);
    const template = document.getElementById('moTemplate').value;
    fetch('/api/create_monitoring', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, interfaces, ips, threshold, template })
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            showNotification(data.message, 'success');
            loadMonitoringObjects();
        } else {
            showNotification(data.message, 'error');
        }
        console.log("Создание объекта мониторинга:", data);
    })
    .catch(error => {
        showNotification(`Error: ${error}`, 'error');
        console.error("Ошибка создания объекта мониторинга:", error);
    });
}

function setThreshold() {
    const name = document.getElementById('thresholdMO').value;
    const threshold = parseInt(document.getElementById('thresholdValue').value);
    fetch('/api/set_threshold', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, threshold })
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            showNotification(data.message, 'success');
        } else {
            showNotification(data.message, 'error');
        }
        console.log("Установка порога:", data);
    })
    .catch(error => {
        showNotification(`Error: ${error}`, 'error');
        console.error("Ошибка установки порога:", error);
    });
}

function setTemplate() {
    const name = document.getElementById('counterMO').value;
    const template = document.getElementById('counterTemplate').value;
    fetch('/api/set_template', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, template })
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            showNotification(data.message, 'success');
        } else {
            showNotification(data.message, 'error');
        }
        console.log("Установка шаблона:", data);
    })
    .catch(error => {
        showNotification(`Error: ${error}`, 'error');
        console.error("Ошибка установки шаблона:", error);
    });
}

function setCountermeasure() {
    const ip = document.getElementById('counterIP').value;
    const type = document.getElementById('counterType').value;
    fetch('/api/set_countermeasure', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, type })
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            showNotification(data.message, 'success');
        } else {
            showNotification(data.message, 'error');
        }
        console.log("Добавление контрмеры:", data);
    })
    .catch(error => {
        showNotification(`Error: ${error}`, 'error');
        console.error("Ошибка добавления контрмеры:", error);
    });
}

function removeCountermeasure() {
    const ip = document.getElementById('counterIP').value;
    fetch('/api/remove_countermeasure', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            showNotification(data.message, 'success');
        } else {
            showNotification(data.message, 'error');
        }
        console.log("Удаление контрмеры:", data);
    })
    .catch(error => {
        showNotification(`Error: ${error}`, 'error');
        console.error("Ошибка удаления контрмеры:", error);
    });
}

// Функция для форматирования байтов в читаемые единицы (bps, Kbps, Mbps, Gbps)
function formatBytes(bytes) {
    if (bytes >= 1e9) {
        return (bytes / 1e9).toFixed(1) + ' Gbps';
    } else if (bytes >= 1e6) {
        return (bytes / 1e6).toFixed(1) + ' Mbps';
    } else if (bytes >= 1e3) {
        return (bytes / 1e3).toFixed(1) + ' Kbps';
    } else {
        return bytes.toFixed(0) + ' bps';
    }
}

// Функция для форматирования времени
function formatTimestamp(timestamp) {
    const date = new Date(timestamp * 1000); // Предполагаем, что timestamp в секундах
    const day = date.getDate();
    const month = date.toLocaleString('default', { month: 'short' });
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    const seconds = String(date.getSeconds()).padStart(2, '0');
    return `${day} ${month} ${hours}:${minutes}:${seconds}`;
}

// Цвета для разных контрмер
const countermeasureColors = {
    'whitelist': { border: '#FF4500', background: 'rgba(255, 69, 0, 0.2)' }, // Оранжевый
    'blacklist': { border: '#FFD700', background: 'rgba(255, 215, 0, 0.2)' }, // Желтый
    // Новые контрмеры будут автоматически получать цвета из этого списка
    'rule1': { border: '#1E90FF', background: 'rgba(30, 144, 255, 0.2)' }, // Синий
    'rule2': { border: '#FF69B4', background: 'rgba(255, 105, 180, 0.2)' }, // Розовый
    'rule3': { border: '#8A2BE2', background: 'rgba(138, 43, 226, 0.2)' } // Фиолетовый
};

let chart = null;
function loadChartData() {
    const name = document.getElementById('chartMO').value;
    const range = document.getElementById('chartRange').value;
    fetch(`/api/get_stats?range=${range}`)
        .then(response => response.json())
        .then(stats => {
            console.log("Получены данные для графика:", stats);
            // Инвертируем данные, чтобы новые были справа
            const labels = stats.map(s => formatTimestamp(s.timestamp)).reverse();
            const totalData = stats.map(s => s.total).reverse();

            // Собираем данные по контрмерам
            const countermeasureData = {};
            stats.forEach(stat => {
                for (const [type, value] of Object.entries(stat.countermeasures)) {
                    if (!countermeasureData[type]) {
                        countermeasureData[type] = [];
                    }
                    countermeasureData[type].push(value);
                }
            });
            // Инвертируем данные контрмер
            for (const type in countermeasureData) {
                countermeasureData[type] = countermeasureData[type].reverse();
            }

            // Определяем максимальное значение для оси Y
            const allCounterData = Object.values(countermeasureData).flat();
            const maxValue = Math.max(...totalData, ...allCounterData);
            const maxY = maxValue > 0 ? maxValue * 1.2 : 100; // +20% или минимум 100
            console.log("Максимальное значение трафика:", maxValue, "Максимум оси Y:", maxY);

            // Формируем datasets
            const datasets = [
                {
                    label: 'Total Traffic',
                    data: totalData,
                    borderColor: '#32CD32', // Зеленый
                    borderWidth: 2,
                    fill: false,
                    tension: 0.1
                }
            ];

            // Добавляем линии для каждой контрмеры
            let colorIndex = 0;
            const defaultColors = [
                { border: '#FF4500', background: 'rgba(255, 69, 0, 0.2)' },
                { border: '#FFD700', background: 'rgba(255, 215, 0, 0.2)' },
                { border: '#1E90FF', background: 'rgba(30, 144, 255, 0.2)' },
                { border: '#FF69B4', background: 'rgba(255, 105, 180, 0.2)' },
                { border: '#8A2BE2', background: 'rgba(138, 43, 226, 0.2)' }
            ];
            for (const [type, data] of Object.entries(countermeasureData)) {
                const colors = countermeasureColors[type] || defaultColors[colorIndex % defaultColors.length];
                colorIndex++;
                datasets.push({
                    label: `Filtered by ${type.charAt(0).toUpperCase() + type.slice(1)}`,
                    data: data,
                    borderColor: colors.border,
                    backgroundColor: colors.background,
                    borderWidth: 2,
                    fill: true,
                    tension: 0.1
                });
            }

            const ctx = document.getElementById('statsChart').getContext('2d');
            if (chart) chart.destroy();
            chart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: datasets
                },
                options: {
                    maintainAspectRatio: true,
                    scales: {
                        x: {
                            title: {
                                display: true,
                                text: 'Time',
                                color: '#666',
                                font: { size: 14 }
                            },
                            ticks: {
                                color: '#666',
                                maxTicksLimit: 10,
                                callback: function(value, index, values) {
                                    return labels[index];
                                }
                            },
                            grid: {
                                color: 'rgba(200, 200, 200, 0.2)'
                            }
                        },
                        y: {
                            title: {
                                display: true,
                                text: 'Traffic',
                                color: '#666',
                                font: { size: 14 }
                            },
                            min: 0,
                            max: maxY,
                            ticks: {
                                color: '#666',
                                callback: function(value) {
                                    return formatBytes(value);
                                }
                            },
                            grid: {
                                color: 'rgba(200, 200, 200, 0.2)'
                            }
                        }
                    },
                    plugins: {
                        legend: {
                            labels: {
                                color: '#666',
                                font: { size: 14 }
                            }
                        },
                        tooltip: {
                            enabled: true,
                            backgroundColor: 'rgba(0, 0, 0, 0.7)',
                            titleColor: '#fff',
                            bodyColor: '#fff',
                            borderColor: '#666',
                            borderWidth: 1,
                            callbacks: {
                                label: function(context) {
                                    let label = context.dataset.label || '';
                                    if (label) {
                                        label += ': ';
                                    }
                                    label += formatBytes(context.parsed.y);
                                    return label;
                                }
                            }
                        }
                    }
                }
            });
            console.log("График обновлён");
        })
        .catch(error => {
            showNotification(`Failed to load chart data: ${error}`, 'error');
            console.error("Ошибка загрузки данных графика:", error);
        });
}

function updateChartPeriodically() {
    loadChartData();
    setTimeout(updateChartPeriodically, 10000); // Обновление каждые 10 секунд
}

window.onload = function() {
    openTab('Overview');
    loadInterfaces();
    loadMonitoringObjects();
    loadOverview();
    updateChartPeriodically();
};
