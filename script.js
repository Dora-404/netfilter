let chart;
let ws;

function initChart() {
    const ctx = document.getElementById('trafficChart').getContext('2d');
    chart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Total Traffic (bytes)',
                data: [],
                borderColor: 'blue',
                fill: false
            }, {
                label: 'Passed Traffic (bytes)',
                data: [],
                borderColor: 'green',
                fill: false
            }, {
                label: 'Dropped Traffic (bytes)',
                data: [],
                borderColor: 'red',
                fill: false
            }]
        },
        options: {
            responsive: true,
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
                        text: 'Traffic (bytes)'
                    },
                    beginAtZero: true,
                    min: 0 // Устанавливаем минимум 0, чтобы исключить отрицательные значения
                }
            }
        }
    });
}

function updateChart() {
    fetch('/traffic')
        .then(response => response.json())
        .then(data => {
            const interval = parseInt(document.getElementById('interval').value);
            const now = new Date();
            const cutoff = now.getTime() - interval * 1000;

            const labels = [];
            const totalData = [];
            const passedData = [];
            const droppedData = [];

            data.forEach(entry => {
                const timestamp = new Date(entry.timestamp).getTime();
                if (timestamp >= cutoff) {
                    labels.push(new Date(entry.timestamp).toLocaleTimeString());
                    totalData.push(entry.total);
                    passedData.push(entry.wl);
                    droppedData.push(entry.bl);
                }
            });

            chart.data.labels = labels;
            chart.data.datasets[0].data = totalData;
            chart.data.datasets[1].data = passedData;
            chart.data.datasets[2].data = droppedData;
            chart.update();
        });
}

function initWebSocket() {
    ws = new WebSocket('ws://' + window.location.host + '/ws');
    ws.onmessage = function(event) {
        updateChart();
    };
    ws.onclose = function() {
        setTimeout(initWebSocket, 5000);
    };
}

function loadInterfaces() {
    fetch('/api/interfaces')
        .then(response => response.json())
        .then(interfaces => {
            const select = document.getElementById('interface');
            interfaces.forEach(iface => {
                const option = document.createElement('option');
                option.value = iface;
                option.textContent = iface;
                select.appendChild(option);
            });
        });
}

function selectInterface() {
    const iface = document.getElementById('interface').value;
    if (!iface) {
        alert('Please select an interface');
        return;
    }
    fetch('/api/select-interface', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ interface: iface })
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'error') {
            alert(data.message);
        } else {
            alert(data.message);
            updateChart();
        }
    });
}

function loadLists() {
    fetch('/api/lists')
        .then(response => response.json())
        .then(data => {
            const listsDiv = document.getElementById('lists');
            listsDiv.innerHTML = '';

            for (const [listType, lists] of [['whitelists', data.whitelists], ['blacklists', data.blacklists]]) {
                const section = document.createElement('div');
                section.innerHTML = `<h4>${listType.charAt(0).toUpperCase() + listType.slice(1)}</h4>`;
                for (const listName in lists) {
                    const listDiv = document.createElement('div');
                    listDiv.innerHTML = `<strong>${listName}</strong> <button onclick="deleteList('${listType}', '${listName}')">Delete</button>`;
                    const ul = document.createElement('ul');
                    for (const ip in lists[listName]) {
                        const li = document.createElement('li');
                        li.textContent = ip;
                        ul.appendChild(li);
                    }
                    listDiv.appendChild(ul);
                    section.appendChild(listDiv);
                }
                listsDiv.appendChild(section);
            }
        });
}

function createList() {
    const listType = document.getElementById('listType').value;
    const listName = document.getElementById('listName').value;
    fetch('/api/create-list', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ listType, listName })
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            alert(data.error);
        } else {
            alert(data.message);
            loadLists();
        }
    });
}

function manageIP(action) {
    const ip = document.getElementById('ipAddress').value;
    const listType = document.getElementById('listType').value;
    const listName = document.getElementById('listName').value;
    fetch('/api/manage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, listType, listName, action })
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            alert(data.error);
        } else {
            alert(data.message);
            loadLists();
        }
    });
}

function bulkUpdate() {
    const listType = document.getElementById('listType').value;
    const listName = document.getElementById('listName').value;
    const content = document.getElementById('bulkIPs').value;
    fetch('/api/bulk-manage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ listType, listName, content })
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            alert(data.error);
        } else {
            alert(data.message);
            loadLists();
        }
    });
}

function deleteList(listType, listName) {
    fetch('/api/delete-list', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ listType, listName })
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            alert(data.error);
        } else {
            alert(data.message);
            loadLists();
        }
    });
}

window.onload = function() {
    initChart();
    initWebSocket();
    loadInterfaces();
    loadLists();
    updateChart();
    setInterval(updateChart, 1000);
};
