// WebSocket для графиков
const ws = new WebSocket('ws://' + window.location.host + '/ws');

let chart = null;
const ctx = document.getElementById('trafficChart').getContext('2d');

ws.onopen = function() {
    console.log('WebSocket соединение установлено');
};

ws.onmessage = function(event) {
    const data = JSON.parse(event.data);
    console.log('Получены данные:', data);
    updateChart(data);
};

ws.onerror = function(error) {
    console.error('WebSocket ошибка:', error);
};

ws.onclose = function() {
    console.log('WebSocket соединение закрыто');
};

// Инициализация графика
function initChart() {
    chart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Incoming Bytes',
                data: [],
                borderColor: '#36A2EB',
                fill: false
            }, {
                label: 'Passed Bytes',
                data: [],
                borderColor: '#4CAF50',
                fill: false
            }, {
                label: 'Dropped Bytes',
                data: [],
                borderColor: '#FF6384',
                fill: false
            }]
        },
        options: {
            scales: {
                x: { title: { display: true, text: 'Time' } },
                y: { title: { display: true, text: 'Bytes' }, beginAtZero: true }
            }
        }
    });
}

// Обновление графика
function updateChart(data) {
    if (!chart) initChart();

    const timestamp = new Date().toLocaleTimeString();
    chart.data.labels.push(timestamp);
    chart.data.datasets[0].data.push(data.Incoming);
    chart.data.datasets[1].data.push(data.Passed);
    chart.data.datasets[2].data.push(Object.values(data.Dropped).reduce((a, b) => a + b, 0));

    // Ограничим количество точек (например, 20)
    if (chart.data.labels.length > 20) {
        chart.data.labels.shift();
        chart.data.datasets[0].data.shift();
        chart.data.datasets[1].data.shift();
        chart.data.datasets[2].data.shift();
    }

    chart.update();
}

// Функция для получения списков
async function fetchLists() {
    try {
        const response = await fetch('/api/lists');
        const data = await response.json();
        console.log('Списки:', data);
        displayLists(data);
    } catch (error) {
        console.error('Ошибка получения списков:', error);
    }
}

// Функция для добавления IP в список
async function addToList(ip, listType) {
    try {
        const response = await fetch('/api/manage', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ip, listType: listType, action: 'add' })
        });
        const result = await response.text();
        console.log('Результат добавления:', result);
        fetchLists(); // Обновить списки
    } catch (error) {
        console.error('Ошибка добавления IP:', error);
    }
}

// Функция для отображения списков
function displayLists(data) {
    const whitelist = document.getElementById('whitelist');
    const blacklist = document.getElementById('blacklist');
    whitelist.innerHTML = '';
    blacklist.innerHTML = '';

    for (let ip in data.whitelist) {
        const li = document.createElement('li');
        li.textContent = ip;
        whitelist.appendChild(li);
    }

    for (let ip in data.blacklist) {
        const li = document.createElement('li');
        li.textContent = ip;
        blacklist.appendChild(li);
    }
}

// Функция для получения и отображения логов
async function fetchEvents() {
    try {
        const response = await fetch('/api/events');
        const events = await response.json();
        console.log('События:', events);
        displayEvents(events);
    } catch (error) {
        console.error('Ошибка получения событий:', error);
    }
}

function displayEvents(events) {
    const eventsList = document.getElementById('events');
    eventsList.innerHTML = '';
    events.forEach(event => {
        const li = document.createElement('li');
        li.textContent = event;
        eventsList.appendChild(li);
    });
}

// Инициализация при загрузке
document.addEventListener('DOMContentLoaded', () => {
    fetchLists();
    fetchEvents();
    // WebSocket автоматически начнёт обновлять график
});
