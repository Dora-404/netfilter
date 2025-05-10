// WebSocket для графиков
const ws = new WebSocket('ws://192.168.1.10:8080/ws');

let chart = null;
const ctx = document.getElementById('trafficChart').getContext('2d');
let allData = [];
let currentUnit = 'B';
let unitFactor = 1;
let customRange = null;
let customDateRange = null;
let listsData = { whitelists: {}, blacklists: {} };
let currentListType = '';

ws.onopen = function() {
    console.log('WebSocket соединение установлено');
};

ws.onmessage = function(event) {
    const data = JSON.parse(event.data);
    console.log('Получены данные:', data);
    const newEntry = {
        timestamp: new Date(),
        incoming: data.Incoming,
        passed: data.Passed,
        dropped: data.Dropped.Blacklist
    };
    allData.push(newEntry);
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

// Функция для определения единицы измерения
function determineUnit(maxValue) {
    if (maxValue >= 1e9) { currentUnit = 'GB'; unitFactor = 1e9; }
    else if (maxValue >= 1e6) { currentUnit = 'MB'; unitFactor = 1e6; }
    else if (maxValue >= 1e3) { currentUnit = 'KB'; unitFactor = 1e3; }
    else { currentUnit = 'B'; unitFactor = 1; }
}

// Инициализация графика
function initChart() {
    chart = new Chart(ctx, {
        type: 'line',
        data: { labels: [], datasets: [
            { label: 'Total Traffic', data: [], borderColor: '#36A2EB', fill: false, borderWidth: 2, pointRadius: 0 },
            { label: 'Whitelist Passed', data: [], borderColor: '#4CAF50', fill: false, borderWidth: 2, pointRadius: 0 },
            { label: 'Blacklist Dropped', data: [], borderColor: '#FF6384', fill: false, borderWidth: 2, pointRadius: 0 }
        ]},
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            scales: { x: { title: { display: true, text: 'Time' }, ticks: { maxTicksLimit: 10 } },
                      y: { title: { display: true, text: 'Traffic' }, beginAtZero: true, suggestedMax: 5000,
                           ticks: { callback: value => (value / unitFactor).toFixed(2) + ' ' + currentUnit } } },
            plugins: {
                zoom: {
                    zoom: { wheel: { enabled: false }, drag: { enabled: true, modifierKey: null,
                        onComplete: ({chart}) => {
                            const xScale = chart.scales.x;
                            const minIndex = Math.floor(xScale.getValueForPixel(xScale.left));
                            const maxIndex = Math.ceil(xScale.getValueForPixel(xScale.right));
                            if (minIndex >= 0 && maxIndex < allData.length) {
                                customRange = [minIndex, maxIndex];
                                customDateRange = null;
                                updateCustomRangeOption();
                            }
                        }
                    }, mode: 'x' },
                    pan: { enabled: true, mode: 'x' },
                    limits: { x: { min: 'original', max: 'original' } }
                }
            }
        }
    });
    ctx.canvas.addEventListener('dblclick', () => {
        chart.resetZoom();
        customRange = null;
        customDateRange = null;
        updateCustomRangeOption();
        updateChartRange();
    });
}

// Обновление опции кастомного диапазона
function updateCustomRangeOption() {
    const select = document.getElementById('timeRange');
    let customOption = select.querySelector('option[value="custom"]');
    let dateOption = select.querySelector('option[value="date"]');

    if (customRange && !customOption) {
        customOption = document.createElement('option');
        customOption.value = 'custom';
        customOption.text = `Custom (${new Date(allData[customRange[0]].timestamp).toLocaleTimeString()} - ${new Date(allData[customRange[1]].timestamp).toLocaleTimeString()})`;
        select.appendChild(customOption);
        select.value = 'custom';
    } else if (!customRange && customOption) {
        customOption.remove();
    }

    if (customDateRange && !dateOption) {
        dateOption = document.createElement('option');
        dateOption.value = 'date';
        dateOption.text = `Date Range (${customDateRange[0].toLocaleString()} - ${customDateRange[1].toLocaleString()})`;
        select.appendChild(dateOption);
        select.value = 'date';
    } else if (!customDateRange && dateOption) {
        dateOption.remove();
    }

    if (!customRange && !customDateRange && (select.value === 'custom' || select.value === 'date')) {
        select.value = 'all';
    }
}

// Фильтрация данных по диапазону
function filterDataByRange(range) {
    if (range === 'custom' && customRange) return allData.slice(customRange[0], customRange[1] + 1);
    if (range === 'date' && customDateRange) {
        const [startDate, endDate] = customDateRange;
        return allData.filter(entry => new Date(entry.timestamp) >= startDate && new Date(entry.timestamp) <= endDate);
    }
    const now = new Date();
    let cutoffTime;
    switch (range) {
        case '5m': cutoffTime = new Date(now.getTime() - 5 * 60 * 1000); break;
        case '30m': cutoffTime = new Date(now.getTime() - 30 * 60 * 1000); break;
        case '1h': cutoffTime = new Date(now.getTime() - 60 * 60 * 1000); break;
        case 'all': default: return allData;
    }
    return allData.filter(entry => new Date(entry.timestamp) >= cutoffTime);
}

// Применение кастомного диапазона по датам
function applyCustomDateRange() {
    const startInput = document.getElementById('startDateTime').value;
    const endInput = document.getElementById('endDateTime').value;
    if (!startInput || !endInput) {
        showAlert('Пожалуйста, выберите начальную и конечную дату', 'danger');
        return;
    }
    const startDate = new Date(startInput);
    const endDate = new Date(endInput);
    if (startDate >= endDate) {
        showAlert('Начальная дата должна быть меньше конечной', 'danger');
        return;
    }
    customDateRange = [startDate, endDate];
    customRange = null;
    updateCustomRangeOption();
    updateChartRange();
}

// Обновление графика
function updateChartRange() {
    if (!chart) initChart();
    const range = document.getElementById('timeRange').value;
    const filteredData = filterDataByRange(range);

    let dataToShow = filteredData;
    if (range === 'custom' && customRange) {
        const [startIndex, endIndex] = customRange;
        if (startIndex >= 0 && endIndex < allData.length && startIndex <= endIndex) {
            const startGlobalIndex = allData.findIndex(entry => entry.timestamp.getTime() === filteredData[0].timestamp.getTime());
            const localStart = Math.max(0, startIndex - startGlobalIndex);
            const localEnd = Math.min(filteredData.length - 1, endIndex - startGlobalIndex);
            if (localStart <= localEnd) {
                dataToShow = filteredData.slice(localStart, localEnd + 1);
            } else {
                customRange = null;
                dataToShow = filteredData;
            }
        } else {
            customRange = null;
            dataToShow = filteredData;
        }
    }

    chart.data.labels = dataToShow.map(entry => new Date(entry.timestamp).toLocaleTimeString());
    chart.data.datasets[0].data = dataToShow.map(entry => entry.incoming);
    chart.data.datasets[1].data = dataToShow.map(entry => entry.passed);
    chart.data.datasets[2].data = dataToShow.map(entry => entry.dropped);

    const allValues = [...chart.data.datasets[0].data, ...chart.data.datasets[1].data, ...chart.data.datasets[2].data];
    determineUnit(Math.max(...allValues, 0));
    const maxInUnits = Math.max(...allValues, 0) / unitFactor;
    chart.options.scales.y.suggestedMax = maxInUnits * 1.2 < 5 ? 5 : maxInUnits * 1.2;
    chart.update();
}

// Обновление каждые 10 секунд
function scheduleUpdate() {
    const now = new Date();
    const nextUpdate = new Date(now);
    nextUpdate.setSeconds(Math.ceil(now.getSeconds() / 10) * 10);
    if (nextUpdate <= now) nextUpdate.setSeconds(nextUpdate.getSeconds() + 10);
    setTimeout(() => {
        updateChartRange();
        scheduleUpdate();
    }, nextUpdate - now);
}

scheduleUpdate();

// Обработка списков
async function fetchLists() {
    try {
        const response = await fetch('/api/lists');
        const data = await response.json();
        console.log('Списки:', data);
        listsData = data;
        displayLists();
        updateCountermeasureStatus();
    } catch (error) {
        console.error('Ошибка получения списков:', error);
    }
}

function displayLists() {
    const wlContainer = document.querySelector('.lists[data-type="whitelist"]');
    const blContainer = document.querySelector('.lists[data-type="blacklist"]');
    wlContainer.innerHTML = '';
    blContainer.innerHTML = '';

    for (let listName in listsData.whitelists) {
        const listDiv = document.createElement('div');
        listDiv.className = 'list mb-2';
        listDiv.innerHTML = `<strong>${listName}</strong>
            <button class="btn btn-secondary btn-sm ms-2" onclick="openEditListModal('whitelist', '${listName}')">Edit</button>
            <button class="btn btn-danger btn-sm ms-2" onclick="deleteList('whitelist', '${listName}')">Delete</button>`;
        const ul = document.createElement('ul');
        for (let ip in listsData.whitelists[listName]) {
            const li = document.createElement('li');
            li.className = 'list-item';
            li.innerHTML = `<span>${ip}</span><button class="btn btn-danger btn-sm ms-2" onclick="removeFromList('${ip}', 'whitelist', '${listName}')">Remove</button>`;
            ul.appendChild(li);
        }
        listDiv.appendChild(ul);
        wlContainer.appendChild(listDiv);
    }

    for (let listName in listsData.blacklists) {
        const listDiv = document.createElement('div');
        listDiv.className = 'list mb-2';
        listDiv.innerHTML = `<strong>${listName}</strong>
            <button class="btn btn-secondary btn-sm ms-2" onclick="openEditListModal('blacklist', '${listName}')">Edit</button>
            <button class="btn btn-danger btn-sm ms-2" onclick="deleteList('blacklist', '${listName}')">Delete</button>`;
        const ul = document.createElement('ul');
        for (let ip in listsData.blacklists[listName]) {
            const li = document.createElement('li');
            li.className = 'list-item';
            li.innerHTML = `<span>${ip}</span><button class="btn btn-danger btn-sm ms-2" onclick="removeFromList('${ip}', 'blacklist', '${listName}')">Remove</button>`;
            ul.appendChild(li);
        }
        listDiv.appendChild(ul);
        blContainer.appendChild(listDiv);
    }
}

async function createNewList() {
    const listName = document.getElementById('newListName').value.trim();
    if (!listName) {
        showAlert('Введите имя списка', 'danger');
        return;
    }
    try {
        const response = await fetch('/api/create-list', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({listType: currentListType, listName})
        });
        const result = await response.json();
        if (response.ok) {
            fetchLists();
            showAlert(`Список ${listName} создан`, 'success');
            bootstrap.Modal.getInstance(document.getElementById('createListModal')).hide();
        } else {
            showAlert(`Ошибка: ${result.error}`, 'danger');
        }
    } catch (error) {
        console.error('Ошибка:', error);
        showAlert(`Ошибка создания списка: ${error.message}`, 'danger');
    }
}

async function deleteList(listType, listName) {
    try {
        const response = await fetch('/api/delete-list', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({listType, listName})
        });
        const result = await response.json();
        if (response.ok) {
            fetchLists();
            showAlert(`Список ${listName} удалён`, 'success');
        } else {
            showAlert(`Ошибка: ${result.error}`, 'danger');
        }
    } catch (error) {
        console.error('Ошибка:', error);
        showAlert(`Ошибка удаления списка: ${error.message}`, 'danger');
    }
}

async function saveListContent() {
    const listType = document.querySelector('#listModal').getAttribute('data-list');
    const listName = document.querySelector('#listModal').getAttribute('data-list-name');
    const content = document.getElementById('listContent').value.trim();
    try {
        const response = await fetch('/api/bulk-manage', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({listType, listName, content})
        });
        const result = await response.json();
        console.log('Результат:', result);
        fetchLists();
        showAlert(`Список ${listName} обновлён`, 'success');
        bootstrap.Modal.getInstance(document.getElementById('listModal')).hide();
    } catch (error) {
        console.error('Ошибка:', error);
        showAlert(`Ошибка обновления ${listName}: ${error.message}`, 'danger');
    }
}

async function removeFromList(ip, listType, listName) {
    try {
        const response = await fetch('/api/manage', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ip, listType, listName, action: 'remove'})
        });
        const result = await response.json();
        console.log('Удаление:', result);
        fetchLists();
        showAlert(`IP ${ip} удалён из ${listName}`, 'success');
    } catch (error) {
        console.error('Ошибка:', error);
        showAlert(`Ошибка удаления ${ip} из ${listName}: ${error.message}`, 'danger');
    }
}

function openCreateListModal(listType) {
    currentListType = listType;
    document.getElementById('newListName').value = '';
    new bootstrap.Modal(document.getElementById('createListModal')).show();
}

function openEditListModal(listType, listName) {
    document.getElementById('listModal').setAttribute('data-list', listType);
    document.getElementById('listModal').setAttribute('data-list-name', listName);
    document.getElementById('listModalLabel').textContent = `Edit ${listName}`;
    const content = [];
    const targetList = listType === 'whitelist' ? listsData.whitelists[listName] : listsData.blacklists[listName];
    for (let ip in targetList) content.push(ip);
    document.getElementById('listContent').value = content.join('\n');
    new bootstrap.Modal(document.getElementById('listModal')).show();
}

function updateCountermeasureStatus() {
    document.querySelectorAll('.countermeasure-item').forEach(item => {
        const type = item.getAttribute('data-type');
        const checkbox = item.querySelector('input[type="checkbox"]');
        const status = item.querySelector('.status');
        status.className = 'status ' + (checkbox.checked ? 'enabled' : 'disabled');
        status.textContent = checkbox.checked ? 'Enabled' : 'Disabled';
    });
}

// Обработка событий
async function fetchEvents() {
    try {
        const response = await fetch('/api/events');
        const events = await response.json();
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

// Уведомления в верхнем правом углу
function showAlert(message, type = 'success') {
    const notifications = document.getElementById('notifications');
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
    alertDiv.role = 'alert';
    alertDiv.style.marginBottom = '10px';
    alertDiv.innerHTML = `${message}<button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>`;
    notifications.appendChild(alertDiv);
    setTimeout(() => alertDiv.remove(), 3000);
}

document.addEventListener('DOMContentLoaded', () => {
    fetchLists();
    fetchEvents();

    document.querySelectorAll('.countermeasure-item input[type="checkbox"]').forEach(checkbox => {
        checkbox.addEventListener('change', updateCountermeasureStatus);
    });

    updateChartRange();
});
