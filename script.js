// WebSocket для графиков
const ws = new WebSocket('ws://192.168.1.10:8080/ws');

let chart = null;
const ctx = document.getElementById('trafficChart').getContext('2d');
let allData = []; // Храним все данные с начала
let currentUnit = 'B'; // Текущая единица измерения (B, KB, MB, GB)
let unitFactor = 1; // Множитель для конвертации
let customRange = null; // Хранит кастомный диапазон [startIndex, endIndex]

ws.onopen = function() {
    console.log('WebSocket соединение установлено');
};

ws.onmessage = function(event) {
    const data = JSON.parse(event.data);
    console.log('Получены данные:', data);
    allData.push({
        timestamp: new Date(),
        incoming: data.Incoming,
        passed: data.Passed,
        dropped: data.Dropped.Blacklist
    });
    // Обновляем только если это время для синхронизированного обновления
    const now = new Date();
    if (now.getSeconds() % 10 === 0 && now.getMilliseconds() < 500) {
        updateChartRange();
    }
};

ws.onerror = function(error) {
    console.error('WebSocket ошибка:', error);
};

ws.onclose = function() {
    console.log('WebSocket соединение закрыто');
};

// Функция для определения единицы измерения и множителя
function determineUnit(maxValue) {
    if (maxValue >= 1e9) { // >= 1 GB
        currentUnit = 'GB';
        unitFactor = 1e9;
    } else if (maxValue >= 1e6) { // >= 1 MB
        currentUnit = 'MB';
        unitFactor = 1e6;
    } else if (maxValue >= 1e3) { // >= 1 KB
        currentUnit = 'KB';
        unitFactor = 1e3;
    } else {
        currentUnit = 'B';
        unitFactor = 1;
    }
}

// Инициализация графика
function initChart() {
    chart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Total Traffic',
                    data: [],
                    borderColor: '#36A2EB',
                    fill: false,
                    borderWidth: 2,
                    pointRadius: 0
                },
                {
                    label: 'Whitelist Passed',
                    data: [],
                    borderColor: '#4CAF50',
                    fill: false,
                    borderWidth: 2,
                    pointRadius: 0
                },
                {
                    label: 'Blacklist Dropped',
                    data: [],
                    borderColor: '#FF6384',
                    fill: false,
                    borderWidth: 2,
                    pointRadius: 0
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            scales: {
                x: {
                    title: {
                        display: true,
                        text: 'Time'
                    },
                    ticks: {
                        maxTicksLimit: 10
                    }
                },
                y: {
                    title: {
                        display: true,
                        text: 'Traffic'
                    },
                    beginAtZero: true,
                    suggestedMax: 5000,
                    ticks: {
                        callback: function(value) {
                            const val = value / unitFactor;
                            return val.toFixed(2) + ' ' + currentUnit;
                        }
                    }
                }
            },
            plugins: {
                zoom: {
                    zoom: {
                        wheel: {
                            enabled: false
                        },
                        drag: {
                            enabled: true,
                            modifierKey: null,
                            onComplete: ({chart}) => {
                                const {min, max} = chart.scales.x.getRange();
                                const startIndex = allData.findIndex(entry => entry.timestamp.toLocaleTimeString() === min);
                                const endIndex = allData.findIndex(entry => entry.timestamp.toLocaleTimeString() === max);
                                if (startIndex !== -1 && endIndex !== -1) {
                                    customRange = [startIndex, endIndex];
                                    updateCustomRangeOption();
                                }
                            }
                        },
                        mode: 'x'
                    },
                    pan: {
                        enabled: true,
                        mode: 'x'
                    },
                    limits: {
                        x: { min: 'original', max: 'original' }
                    }
                }
            }
        }
    });

    // Сброс зума по двойному клику
    ctx.canvas.addEventListener('dblclick', () => {
        chart.resetZoom();
        customRange = null;
        updateCustomRangeOption();
    });
}

// Функция для обновления выпадающего списка с кастомным диапазоном
function updateCustomRangeOption() {
    const select = document.getElementById('timeRange');
    const customOption = select.querySelector('option[value="custom"]');
    if (customRange && !customOption) {
        const option = document.createElement('option');
        option.value = 'custom';
        option.text = `Custom (${new Date(allData[customRange[0]].timestamp).toLocaleTimeString()} - ${new Date(allData[customRange[1]].timestamp).toLocaleTimeString()})`;
        select.appendChild(option);
        select.value = 'custom';
    } else if (!customRange && customOption) {
        customOption.remove();
        select.value = 'all'; // Возвращаем к умолчанию
    }
}

// Функция для фильтрации данных по временному диапазону
function filterDataByRange(range) {
    if (range === 'custom' && customRange) {
        return allData.slice(customRange[0], customRange[1] + 1);
    }

    const now = new Date();
    let cutoffTime;

    switch (range) {
        case '5m':
            cutoffTime = new Date(now.getTime() - 5 * 60 * 1000);
            break;
        case '30m':
            cutoffTime = new Date(now.getTime() - 30 * 60 * 1000);
            break;
        case '1h':
            cutoffTime = new Date(now.getTime() - 60 * 60 * 1000);
            break;
        case 'all':
        default:
            return allData; // Возвращаем все данные
    }

    return allData.filter(entry => entry.timestamp >= cutoffTime);
}

// Обновление графика с учётом диапазона
function updateChartRange() {
    if (!chart) initChart();

    const range = document.getElementById('timeRange').value;
    const filteredData = filterDataByRange(range);

    // Сбрасываем зум перед обновлением данных, если не кастомный диапазон
    if (range !== 'custom') {
        chart.resetZoom();
    }

    // Обновляем метки и данные
    chart.data.labels = filteredData.map(entry => entry.timestamp.toLocaleTimeString());
    const incomingData = filteredData.map(entry => entry.incoming);
    const passedData = filteredData.map(entry => entry.passed);
    const droppedData = filteredData.map(entry => entry.dropped);
    chart.data.datasets[0].data = incomingData;
    chart.data.datasets[1].data = passedData;
    chart.data.datasets[2].data = droppedData;

    // Находим максимальное значение для оси Y
    const allValues = [
        ...incomingData,
        ...passedData,
        ...droppedData
    ];
    const maxValue = Math.max(...allValues, 0);

    // Определяем единицу измерения
    determineUnit(maxValue);

    // Обновляем верхнюю границу оси Y (20% сверху от максимума в текущих единицах)
    const maxInUnits = maxValue / unitFactor;
    const upperLimit = maxInUnits * 1.2;
    chart.options.scales.y.suggestedMax = upperLimit < 5 ? 5 : upperLimit;

    chart.update();
}

// Синхронизированное обновление раз в 10 секунд
function scheduleUpdate() {
    const now = new Date();
    const nextUpdate = new Date(now);
    nextUpdate.setSeconds(Math.ceil(now.getSeconds() / 10) * 10);
    if (nextUpdate <= now) nextUpdate.setSeconds(nextUpdate.getSeconds() + 10);

    const delay = nextUpdate - now;
    setTimeout(() => {
        updateChartRange();
        scheduleUpdate(); // Запускаем следующее обновление
    }, delay);
}

scheduleUpdate();

// Функции для списков и событий
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

async function addToList(ip, listType) {
    try {
        const response = await fetch('/api/manage', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ip: ip, listType: listType, action: 'add'})
        });
        const result = await response.text();
        console.log('Результат добавления:', result);
        fetchLists();
    } catch (error) {
        console.error('Ошибка добавления IP:', error);
    }
}

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

document.addEventListener('DOMContentLoaded', () => {
    fetchLists();
    fetchEvents();
});
