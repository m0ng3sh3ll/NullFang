// Variáveis globais
let selectedDomain = '';
let availableDomains = [];

// Função para carregar domínios disponíveis
async function loadDomains() {
    try {
        console.log('Loading domains...');
        const response = await fetch('/domains');
        console.log('API /domains response:', response);
        
        if (!response.ok) {
            throw new Error(`Error loading domains: ${response.status} ${response.statusText}`);
        }
        
        availableDomains = await response.json();
        console.log('Domains loaded:', availableDomains);
        
        const domainSelector = document.getElementById('domainSelector');
        if (!domainSelector) {
            console.error('Element domainSelector not found');
            return;
        }
        
        domainSelector.innerHTML = '<option value="">All domains</option>';
        
        availableDomains.forEach(domain => {
            const option = document.createElement('option');
            option.value = domain;
            option.textContent = domain;
            domainSelector.appendChild(option);
        });
        
        console.log('Domain selector updated with', availableDomains.length, 'domains');
        
        // Restaurar domínio selecionado se existir
        const savedDomain = localStorage.getItem('selectedDomain');
        if (savedDomain && availableDomains.includes(savedDomain)) {
            domainSelector.value = savedDomain;
            selectedDomain = savedDomain;
            console.log('Domain restored:', savedDomain);
        }
    } catch (error) {
        console.error('Error loading domains:', error);
        const domainSelector = document.getElementById('domainSelector');
        if (domainSelector) {
            domainSelector.innerHTML = '<option value="">Error loading domains</option>';
        }
    }
}

// Função para atualizar o domínio selecionado
function updateSelectedDomain(domain) {
    console.log('Updating selected domain to:', domain);
    selectedDomain = domain;
    localStorage.setItem('selectedDomain', domain);
    
    // Recarregar conteúdo da página atual
    const currentRoute = window.location.pathname;
    console.log('Reloading content for route:', currentRoute);
    loadContent(currentRoute);
}

// Função para obter parâmetros de domínio para requisições
function getDomainParams() {
    const params = selectedDomain ? `?domain=${encodeURIComponent(selectedDomain)}` : '';
    console.log('Domain parameters for request:', params);
    return params;
}

// Rotas da aplicação
const routes = {
    '/': 'home',
    '/documents': 'documents',
    '/analysis': 'analysis',
    '/settings': 'settings',
    '/suggestions': 'suggestions',
    '/infrastructure': 'infrastructure'
};

// Função para navegação
function navigate(route) {
    history.pushState(null, '', route);
    loadContent(route);
}

// Função para carregar conteúdo
function loadContent(route) {
    const mainContent = document.getElementById('mainContent');
    if (!mainContent) return;

    switch (route) {
        case '/':
            mainContent.innerHTML = `
                <div class="container mt-4">
                    <h2>Welcome to the Classification System</h2>
                    <div class="row mt-4">
                        <div class="col-md-6">
                            <div class="card">
                                <div class="card-body">
                                    <h5 class="card-title">Documents</h5>
                                    <p class="card-text">Manage and classify your documents.</p>
                                    <a href="#" onclick="navigate('/documents')" class="btn btn-primary">View Documents</a>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="card">
                                <div class="card-body">
                                    <h5 class="card-title">Analysis</h5>
                                    <p class="card-text">Visualize statistics and sensitivity map.</p>
                                    <a href="#" onclick="navigate('/analysis')" class="btn btn-primary">View Analysis</a>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            break;

        case '/documents':
            mainContent.innerHTML = `
                <div class="container mt-4">
                    <h2>Documents</h2>
                    <div class="mb-3">
                        <button class="btn btn-primary" onclick="classifySelected()">Classify Selected</button>
                        <button class="btn btn-secondary" onclick="autoClassifyDocuments()">Classify Automatically</button>
                    </div>
                    <div class="table-responsive">
                        <table class="table table-striped" id="documentsTable">
                            <thead>
                                <tr>
                                    <th><input type="checkbox" id="selectAll"></th>
                                    <th>Name</th>
                                    <th>Host</th>
                                    <th>Share</th>
                                    <th>Domain</th>
                                    <th>Size</th>
                                    <th>Last Modified</th>
                                    <th>Search Parameter</th>
                                    <th>Searched Value</th>
                                    <th>Found Pattern</th>
                                    <th>Match Type</th>
                                    <th>Classification</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody></tbody>
                        </table>
                    </div>
                </div>
            `;
            loadDocuments();
            break;

        case '/analysis':
            mainContent.innerHTML = `
                <div class="container mt-4">
                    <h2>Analysis of Documents</h2>
                    <p class="text-muted">Visual summary of classifications and patterns found. Ready for evidence in report.</p>
                    <div class="row mb-4">
                        <div class="col-md-6">
                            <canvas id="classPieChart"></canvas>
                        </div>
                        <div class="col-md-6">
                            <table class="table table-bordered" id="classSummaryTable">
                                <thead class="table-light">
                                    <tr>
                                        <th>Classification</th>
                                        <th>Quantity</th>
                                        <th>Percentage</th>
                                    </tr>
                                </thead>
                                <tbody></tbody>
                            </table>
                        </div>
                    </div>
                    <div class="row mb-4">
                        <div class="col-md-12">
                            <h5>Sensitive Patterns Found</h5>
                            <canvas id="patternBarChart"></canvas>
                        </div>
                    </div>
                    <div class="row">
                        <div class="col-md-12 text-end text-muted">
                            <small>Analysis generated on: <span id="analysisDate"></span></small>
                        </div>
                    </div>
                </div>
            `;
            loadAnalysisCharts();
            break;

        case '/settings':
            mainContent.innerHTML = `
                <div class="container mt-4">
                    <h2>Settings</h2>
                    <div class="row">
                        <div class="col-md-6">
                            <div class="card">
                                <div class="card-body">
                                    <h5 class="card-title">Classifications</h5>
                                    <button class="btn btn-primary mb-3" onclick="showNewClassificationModal()">New Classification</button>
                                    <div class="table-responsive">
                                        <table class="table">
                                            <thead>
                                                <tr>
                                                    <th>Name</th>
                                                    <th>Description</th>
                                                    <th>Level</th>
                                                    <th>Color</th>
                                                    <th>Actions</th>
                                                </tr>
                                            </thead>
                                            <tbody id="classificationsList"></tbody>
                                        </table>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="card">
                                <div class="card-body">
                                    <h5 class="card-title">Classification Rules</h5>
                                    <button class="btn btn-primary mb-3" onclick="showNewRuleModal()">New Rule</button>
                                    <div class="table-responsive">
                                        <table class="table">                                        
                                            <tbody id="rulesList"></tbody>
                                        </table>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            loadClassifications();
            renderClassificationsTable();
            loadRules();
            break;

        case '/suggestions':
            mainContent.innerHTML = `
                <div class="container mt-4">
                    <h2>Classification Suggestions</h2>
                    <div class="mb-3">
                        <button class="btn btn-success" id="applyAllSuggestions">Apply All Suggestions</button>
                    </div>
                    <div class="table-responsive">
                        <table class="table table-striped" id="suggestionsTable">
                            <thead>
                                <tr>
                                    <th>Name</th>
                                    <th>Current Classification</th>
                                    <th>Reason for Suggestion</th>
                                    <th style="text-align:right;">Actions</th>
                                </tr>
                            </thead>
                            <tbody></tbody>
                        </table>
                    </div>
                </div>
            `;
            loadSuggestions();
            break;

        case '/infrastructure':
            mainContent.innerHTML = `
                <div class="container-fluid mt-4">
                    <div class="row mb-4">
                        <div class="col">
                            <h2>Infrastructure Map</h2>
                            <p class="text-muted">Visualization of discovered infrastructure and access relationships.</p>
                        </div>
                        <div class="col-auto">
                            <button class="btn btn-primary" onclick="populateInfrastructure()">
                                Update Data
                            </button>
                        </div>
                    </div>

                    <div class="row">
                        <div class="col-md-3">
                            <div class="card mb-4">
                                <div class="card-header">
                                    <h5 class="card-title mb-0">Filters</h5>
                                </div>
                                <div class="card-body">
                                    <div class="mb-3">
                                        <label class="form-label">Node Type</label>
                                        <div class="form-check">
                                            <input class="form-check-input" type="checkbox" id="showHosts" checked>
                                            <label class="form-check-label" for="showHosts">Hosts</label>
                                        </div>
                                        <div class="form-check">
                                            <input class="form-check-input" type="checkbox" id="showUsers" checked>
                                            <label class="form-check-label" for="showUsers">Users</label>
                                        </div>
                                        <div class="form-check">
                                            <input class="form-check-input" type="checkbox" id="showShares" checked>
                                            <label class="form-check-label" for="showShares">Shares</label>
                                        </div>
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">Access Type</label>
                                        <div class="form-check">
                                            <input class="form-check-input" type="checkbox" id="showRead" checked>
                                            <label class="form-check-label" for="showRead">Read</label>
                                        </div>
                                        <div class="form-check">
                                            <input class="form-check-input" type="checkbox" id="showWrite" checked>
                                            <label class="form-check-label" for="showWrite">Write</label>
                                        </div>
                                        <div class="form-check">
                                            <input class="form-check-input" type="checkbox" id="showAdmin" checked>
                                            <label class="form-check-label" for="showAdmin">Administrator</label>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <div class="card">
                                <div class="card-header">
                                    <h5 class="card-title mb-0">Statistics</h5>
                                </div>
                                <div class="card-body">
                                    <div id="infrastructureStats">
                                        <p>Loading statistics...</p>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div class="col-md-9">
                            <div class="card">
                                <div class="card-body">
                                    <div id="infrastructureGraph" style="height: 600px;">
                                        <p class="text-center">Loading graph...</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            loadInfrastructureData();
            break;

        default:
            mainContent.innerHTML = '<div class="container mt-4"><h2>Page not found</h2></div>';
    }
}

// Funções auxiliares
function formatSize(bytes) {
    const units = ['B', 'KB', 'MB', 'GB'];
    let size = bytes;
    let unitIndex = 0;
    while (size >= 1024 && unitIndex < units.length - 1) {
        size /= 1024;
        unitIndex++;
    }
    return `${size.toFixed(2)} ${units[unitIndex]}`;
}

function formatDate(dateStr) {
    return new Date(dateStr).toLocaleString();
}

function getClassificationColor(level) {
    const colors = {
        1: '#28a745', // Verde
        2: '#17a2b8', // Azul
        3: '#ffc107', // Amarelo
        4: '#fd7e14', // Laranja
        5: '#dc3545'  // Vermelho
    };
    return colors[level] || '#6c757d';
}

// Funções de carregamento de dados
function loadDocuments() {
    const domainParams = getDomainParams();
    fetch(`/documents${domainParams}`)
        .then(response => response.json())
        .then(documents => {
            const tbody = document.querySelector('#documentsTable tbody');
            tbody.innerHTML = '';
            
            documents.forEach(doc => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td><input type="checkbox" class="document-checkbox" data-id="${doc.id}"></td>
                    <td>${doc.name}</td>
                    <td>${doc.host || ''}</td>
                    <td>${doc.share || ''}</td>
                    <td>${doc.domain || ''}</td>
                    <td>${formatSize(doc.size)}</td>
                    <td>${doc.last_modified}</td>
                    <td>${doc.search_param_type || ''}</td>
                    <td>${doc.search_param_value || ''}</td>
                    <td>${doc.match_pattern || ''}</td>
                    <td>${doc.match_type || ''}</td>
                    <td>
                        ${doc.classification ? 
                            `<span class="badge" style="background-color: ${doc.classification.color}">${doc.classification.name}</span>` 
                            : '<span class="badge bg-secondary">Not classified</span>'}
                    </td>
                    <td>
                        <button class="btn btn-sm btn-primary" onclick="classifyDocument(${doc.id})">
                            Classify
                        </button>
                    </td>
                `;
                tbody.appendChild(tr);
            });

            // Adicionar evento para o checkbox "Selecionar Todos"
            const selectAllCheckbox = document.querySelector('#selectAll');
            if (selectAllCheckbox) {
                selectAllCheckbox.addEventListener('change', function() {
                    const checkboxes = document.querySelectorAll('.document-checkbox');
                    checkboxes.forEach(checkbox => {
                        checkbox.checked = this.checked;
                    });
                });
            }
        })
        .catch(error => {
            console.error('Error loading documents:', error);
            alert('Error loading documents. Please try again.');
        });
}

async function loadAnalysisCharts() {
    const domainParams = getDomainParams();
    
    // Gráfico de pizza e tabela resumo
    const pieCtx = document.getElementById('classPieChart').getContext('2d');
    const tableBody = document.querySelector('#classSummaryTable tbody');
    const dateSpan = document.getElementById('analysisDate');
    // Gráfico de barras
    const barCtx = document.getElementById('patternBarChart').getContext('2d');

    // 1. Buscar estatísticas de classificação
    const statsRes = await fetch(`/analysis/stats${domainParams}`);
    const stats = await statsRes.json();
    const total = stats.reduce((sum, s) => sum + s.document_count, 0);
    const labels = stats.map(s => s.name);
    const data = stats.map(s => s.document_count);
    const colors = stats.map(s => s.color);

    // Gráfico de pizza
    new Chart(pieCtx, {
        type: 'pie',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: colors,
            }]
        },
        options: {
            plugins: {
                legend: { position: 'bottom' },
                title: { display: true, text: 'Distribution of Documents by Classification' }
            }
        }
    });

    // Tabela resumo
    tableBody.innerHTML = stats.map(s => `
        <tr>
            <td><span class="badge" style="background:${s.color};min-width:80px;">${s.name}</span></td>
            <td>${s.document_count}</td>
            <td>${total ? ((s.document_count/total)*100).toFixed(1) : 0}%</td>
        </tr>
    `).join('');

    // 2. Buscar padrões encontrados (usando a rota de sugestões para contar por regra)
    const suggRes = await fetch(`/documents/classification-suggestions${domainParams}`);
    const suggestions = await suggRes.json();
    // Contar quantos documentos cada regra sugeriu
    const patternMap = {};
    suggestions.forEach(s => {
        if (s.rule_name) {
            patternMap[s.rule_name] = (patternMap[s.rule_name] || 0) + 1;
        }
    });
    const patternLabels = Object.keys(patternMap);
    const patternData = Object.values(patternMap);
    // Gráfico de barras
    new Chart(barCtx, {
        type: 'bar',
        data: {
            labels: patternLabels,
            datasets: [{
                label: 'Documents found',
                data: patternData,
                backgroundColor: '#fd7e14',
            }]
        },
        options: {
            plugins: {
                legend: { display: false },
                title: { display: true, text: 'Main Sensitive Patterns Found' }
            },
            scales: {
                x: { title: { display: true, text: 'Rule/Pattern' } },
                y: { title: { display: true, text: 'Quantity' }, beginAtZero: true }
            }
        }
    });

    // Data/hora da análise
    dateSpan.textContent = new Date().toLocaleString();
}

function loadClassifications() {
    fetch('/classifications')
        .then(response => {
            if (!response.ok) {
                throw new Error('Error loading classifications');
            }
            return response.json();
        })
        .then(classifications => {
            const select = document.getElementById('classificationSelect');
            if (!select) {
                console.error('Element classificationSelect not found');
                return;
            }
            
            select.innerHTML = '<option value="">Select a classification...</option>';
            classifications.forEach(c => {
                const option = document.createElement('option');
                option.value = c.id;
                option.textContent = c.name;
                select.appendChild(option);
            });
        })
        .catch(error => {
            console.error('Error loading classifications:', error);
            alert('Error loading classifications. Please try again.');
        });
}

function renderClassificationsTable() {
    fetch('/classifications')
        .then(response => response.json())
        .then(classifications => {
            const tbody = document.getElementById('classificationsList');
            if (!tbody) return;
            tbody.innerHTML = classifications.map(c => `
                <tr>
                    <td>${c.name}</td>
                    <td>${c.description}</td>
                    <td>${c.level}</td>
                    <td>
                        <span style="display:inline-block;width:24px;height:24px;background:${c.color};border-radius:4px;"></span>
                    </td>
                    <td>
                        <!-- Botões de ação, se desejar -->
                    </td>
                </tr>
            `).join('');
        })
        .catch(error => {
            console.error('Erro ao carregar classificações:', error);
        });
}

function loadRules() {
    fetch('/rules')
        .then(response => response.json())
        .then(rules => {
            const tbody = document.getElementById('rulesList');
            tbody.innerHTML = `
                <table class="table">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Description</th>
                            <th>Pattern</th>
                            <th>Type</th>
                            <th>Priority</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${rules.map(rule => `
                            <tr>
                                <td>${rule.name}</td>
                                <td>${rule.description}</td>
                                <td>${rule.match_pattern}</td>
                                <td>${rule.match_type}</td>
                                <td>${rule.priority}</td>
                                <td>
                                    <button class="btn btn-sm btn-primary" onclick="editRule(${rule.id})">Edit</button>
                                    <button class="btn btn-sm btn-danger" onclick="deleteRule(${rule.id})">Delete</button>
                                </td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            `;
        })
        .catch(error => {
            console.error('Error loading rules:', error);
        });
}

async function showNewRuleModal() {
    try {
        const response = await fetch('/classifications');
        const classifications = await response.json();

        const modal = document.createElement('div');
        modal.className = 'modal fade';
        modal.innerHTML = `
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">New Classification Rule</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <form id="ruleForm">
                            <div class="mb-3">
                                <label class="form-label">Name</label>
                                <input type="text" class="form-control" name="name" required>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Description</label>
                                <textarea class="form-control" name="description" rows="2"></textarea>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Search Pattern</label>
                                <input type="text" class="form-control" name="match_pattern" required>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Search Type</label>
                                <select class="form-select" name="match_type" required>
                                    <option value="regex">Regular Expression</option>
                                    <option value="contains">Contains</option>
                                    <option value="exact">Exact Match</option>
                                </select>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Classification</label>
                                <select class="form-select" name="classification_id" required>
                                    <option value="">Select a classification</option>
                                    ${classifications.map(c => `
                                        <option value="${c.id}">${c.name}</option>
                                    `).join('')}
                                </select>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Priority</label>
                                <input type="number" class="form-control" name="priority" value="0" min="0" max="100">
                            </div>
                        </form>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="button" class="btn btn-primary" onclick="createRule()">Create</button>
                    </div>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
        new bootstrap.Modal(modal).show();
    } catch (error) {
        console.error('Error showing new rule modal:', error);
    }
}

async function createRule() {
    const form = document.getElementById('ruleForm');
    const formData = new FormData(form);
    
    const name = formData.get('name');
    const description = formData.get('description');
    const pattern = formData.get('match_pattern');
    const type = formData.get('match_type');
    const classificationId = formData.get('classification_id');
    const priority = formData.get('priority');

    try {
        const response = await fetch('/rules', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                name,
                description,
                match_pattern: pattern,
                match_type: type,
                classification_id: parseInt(classificationId),
                priority: parseInt(priority)
            })
        });

        if (response.ok) {
            loadRules();
            // Fechar o modal de criação
            const createModal = document.querySelector('.modal:not([data-rule-edit])');
            if (createModal) {
                bootstrap.Modal.getInstance(createModal).hide();
                createModal.remove();
            }
        } else {
            const error = await response.json();
            alert('Error creating rule: ' + error.error);
        }
    } catch (error) {
        console.error('Error creating rule:', error);
        alert('Error creating rule: ' + error.message);
    }
}

async function editRule(ruleId) {
    try {
        const [ruleResponse, classificationsResponse] = await Promise.all([
            fetch(`/rules/${ruleId}`),
            fetch('/classifications')
        ]);
        
        const rule = await ruleResponse.json();
        const classifications = await classificationsResponse.json();

        // Remover modal existente se houver
        const existingModal = document.querySelector('.modal[data-rule-edit]');
        if (existingModal) {
            existingModal.remove();
        }

        const modal = document.createElement('div');
        modal.className = 'modal fade';
        modal.setAttribute('data-rule-edit', 'true');
        modal.innerHTML = `
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Edit Classification Rule</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <form id="editRuleForm">
                            <input type="hidden" id="editRuleId" value="${rule.id}">
                            <div class="mb-3">
                                <label class="form-label">Name</label>
                                <input type="text" class="form-control" id="editRuleName" value="${rule.name}" required>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Description</label>
                                <textarea class="form-control" id="editRuleDescription" rows="2">${rule.description || ''}</textarea>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Search Pattern</label>
                                <input type="text" class="form-control" id="editRulePattern" value="${rule.match_pattern}" required>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Search Type</label>
                                <select class="form-select" id="editRuleType" required>
                                    <option value="regex" ${rule.match_type === 'regex' ? 'selected' : ''}>Regular Expression</option>
                                    <option value="contains" ${rule.match_type === 'contains' ? 'selected' : ''}>Contains</option>
                                    <option value="exact" ${rule.match_type === 'exact' ? 'selected' : ''}>Exact Match</option>
                                </select>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Classification</label>
                                <select class="form-select" id="editRuleClassification" required>
                                    <option value="">Select a classification</option>
                                    ${classifications.map(c => `
                                        <option value="${c.id}" ${rule.classification_id === c.id ? 'selected' : ''}>${c.name}</option>
                                    `).join('')}
                                </select>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Priority</label>
                                <input type="number" class="form-control" id="editRulePriority" value="${rule.priority}" min="0" max="100">
                            </div>
                        </form>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="button" class="btn btn-primary" onclick="updateRule(${rule.id})">Update</button>
                    </div>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
        new bootstrap.Modal(modal).show();
    } catch (error) {
        console.error('Error loading rule:', error);
        alert('Error loading rule for editing: ' + error.message);
    }
}

async function updateRule(ruleId) {
    const id = ruleId || document.getElementById('editRuleId').value;
    const name = document.getElementById('editRuleName').value;
    const description = document.getElementById('editRuleDescription').value;
    const pattern = document.getElementById('editRulePattern').value;
    const type = document.getElementById('editRuleType').value;
    const classificationId = document.getElementById('editRuleClassification').value;
    const priority = document.getElementById('editRulePriority').value;

    try {
        const response = await fetch(`/rules/${id}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                name,
                description,
                match_pattern: pattern,
                match_type: type,
                classification_id: parseInt(classificationId),
                priority: parseInt(priority)
            })
        });

        if (response.ok) {
            loadRules();
            // Fechar o modal de edição
            const editModal = document.querySelector('.modal[data-rule-edit]');
            if (editModal) {
                bootstrap.Modal.getInstance(editModal).hide();
                editModal.remove();
            }
        } else {
            const error = await response.json();
            alert('Error updating rule: ' + error.error);
        }
    } catch (error) {
        console.error('Error updating rule:', error);
        alert('Error updating rule: ' + error.message);
    }
}

async function deleteRule(ruleId) {
    if (!confirm('Are you sure you want to delete this rule?')) {
        return;
    }

    try {
        const response = await fetch(`/rules/${ruleId}`, {
            method: 'DELETE'
        });

        if (response.ok) {
            loadRules();
        } else {
            const error = await response.json();
            alert('Error deleting rule: ' + error.error);
        }
    } catch (error) {
        console.error('Error deleting rule:', error);
    }
}

// Event Listeners
document.addEventListener('DOMContentLoaded', () => {
    // Carregar domínios disponíveis
    loadDomains();
    
    // Configurar event listener para o seletor de domínio
    document.getElementById('domainSelector').addEventListener('change', (e) => {
        updateSelectedDomain(e.target.value);
    });

    // Carregar classificações quando o modal for aberto
    document.getElementById('classificationModal').addEventListener('show.bs.modal', loadClassifications);

    // Configurar navegação
    document.querySelectorAll('a[href^="/"]').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            navigate(link.getAttribute('href'));
        });
    });

    // Configurar navegação do histórico
    window.addEventListener('popstate', () => {
        loadContent(window.location.pathname);
    });

    // Carregar conteúdo inicial
    const initialRoute = window.location.pathname || '/';
    loadContent(initialRoute);

    // Adicione outras funções usadas em onclick conforme necessário
    window.navigate = navigate;
    window.populateInfrastructure = populateInfrastructure;
    window.classifySelected = classifySelected;
    window.autoClassifyDocuments = autoClassifyDocuments;
    window.applyClassification = applyClassification;
    window.showNewClassificationModal = showNewClassificationModal;
    window.showNewRuleModal = showNewRuleModal;
    window.createClassification = createClassification;
});

// Funções de manipulação de classificações
async function showClassifyModal(fileId) {
    try {
        const response = await fetch('/classifications');
        const classifications = await response.json();

        const modal = document.createElement('div');
        modal.className = 'modal fade';
        modal.innerHTML = `
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Classify Document</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <form id="classifyForm">
                            <div class="mb-3">
                                <label class="form-label">Classification</label>
                                <select class="form-select" name="classification_id" required>
                                    <option value="">Select a classification</option>
                                    ${classifications.map(c => `
                                        <option value="${c.id}" style="color: ${c.color}">
                                            ${c.name}
                                        </option>
                                    `).join('')}
                                </select>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Notes</label>
                                <textarea class="form-control" name="notes" rows="3"></textarea>
                            </div>
                        </form>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="button" class="btn btn-primary" onclick="classifyDocument(${fileId})">Classify</button>
                    </div>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
        new bootstrap.Modal(modal).show();
    } catch (error) {
        console.error('Error showing classification modal:', error);
    }
}

async function classifyDocument(fileId) {
    try {
        const form = document.getElementById('classifyForm');
        const formData = new FormData(form);
        const data = {
            file_id: fileId,
            classification_id: parseInt(formData.get('classification_id')),
            notes: formData.get('notes')
        };

        const response = await fetch('/documents/classify', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });

        if (response.ok) {
            bootstrap.Modal.getInstance(document.querySelector('.modal')).hide();
            loadDocuments();
        } else {
            const error = await response.json();
            alert('Error classifying document: ' + error.error);
        }
    } catch (error) {
        console.error('Error classifying document:', error);
    }
}

async function removeClassification(fileId) {
    if (!confirm('Are you sure you want to remove the classification of this document?')) {
        return;
    }

    try {
        const response = await fetch(`/documents/classify/${fileId}`, {
            method: 'DELETE'
        });

        if (response.ok) {
            loadDocuments();
        } else {
            const error = await response.json();
            alert('Error removing classification: ' + error.error);
        }
    } catch (error) {
        console.error('Error removing classification:', error);
    }
}

async function bulkClassify() {
    const selectedDocs = Array.from(document.querySelectorAll('.document-checkbox:checked'))
        .map(cb => parseInt(cb.dataset.id));

    if (selectedDocs.length === 0) {
        alert('Select at least one document');
        return;
    }

    try {
        const response = await fetch('/classifications');
        const classifications = await response.json();

        const modal = document.createElement('div');
        modal.className = 'modal fade';
        modal.innerHTML = `
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Classify Documents</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <form id="bulkClassifyForm">
                            <div class="mb-3">
                                <label class="form-label">Classification</label>
                                <select class="form-select" name="classification_id" required>
                                    <option value="">Select a classification</option>
                                    ${classifications.map(c => `
                                        <option value="${c.id}">${c.name}</option>
                                    `).join('')}
                                </select>
                            </div>
                        </form>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="button" class="btn btn-primary" onclick="submitBulkClassify()">Classify</button>
                    </div>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
        new bootstrap.Modal(modal).show();
    } catch (error) {
        console.error('Error showing bulk classification modal:', error);
    }
}

async function submitBulkClassify() {
    try {
        const form = document.getElementById('bulkClassifyForm');
        const formData = new FormData(form);
        const data = {
            document_ids: Array.from(document.querySelectorAll('.document-checkbox:checked'))
                .map(cb => parseInt(cb.dataset.id)),
            classification_id: parseInt(formData.get('classification_id'))
        };

        const response = await fetch('/documents/bulk-classify', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });

        if (response.ok) {
            bootstrap.Modal.getInstance(document.querySelector('.modal')).hide();
            loadDocuments();
        } else {
            const error = await response.json();
            alert('Error classifying documents: ' + error.error);
        }
    } catch (error) {
        console.error('Error classifying documents:', error);
    }
}

function autoClassifyDocuments() {
    navigate('/suggestions');
}

// Função para classificar um documento específico
async function classifyDocument(documentId) {
    window.selectedDocumentIds = [documentId];
    await loadClassifications();
    const modal = new bootstrap.Modal(document.getElementById('classificationModal'));
    modal.show();
}

// Função para classificar documentos selecionados
async function classifySelected() {
    const checkboxes = document.querySelectorAll('.document-checkbox:checked');
    if (checkboxes.length === 0) {
        alert('Please select at least one document to classify.');
        return;
    }

    window.selectedDocumentIds = Array.from(checkboxes).map(cb => parseInt(cb.dataset.id));
    await loadClassifications();
    const modal = new bootstrap.Modal(document.getElementById('classificationModal'));
    modal.show();
}

// Função para aplicar a classificação
function applyClassification() {
    const classificationId = document.getElementById('classificationSelect').value;
    const notes = document.getElementById('classificationNotes').value;
    const selectedIds = window.selectedDocumentIds || [];

    if (!classificationId) {
        alert('Please select a classification.');
        return;
    }

    // Classificar cada documento selecionado
    const promises = selectedIds.map(id => 
        fetch('/documents/classify', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                document_id: id,
                classification_id: parseInt(classificationId),
                notes: notes
            })
        })
    );

    Promise.all(promises)
        .then(() => {
            alert('Documents classified successfully!');
            loadDocuments(); // Recarregar a lista
            const modal = bootstrap.Modal.getInstance(document.getElementById('classificationModal'));
            if (modal) {
                modal.hide();
            }
            // Limpar os campos do modal
            document.getElementById('classificationSelect').value = '';
            document.getElementById('classificationNotes').value = '';
        })
        .catch(error => {
            console.error('Error classifying documents:', error);
            alert('Error classifying documents. Please try again.');
        });
}

function showNewClassificationModal() {
    // Cria o modal dinamicamente
    const modal = document.createElement('div');
    modal.className = 'modal fade';
    modal.innerHTML = `
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">New Classification</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <form id="classificationForm">
                        <div class="mb-3">
                            <label class="form-label">Name</label>
                            <input type="text" class="form-control" name="name" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Description</label>
                            <textarea class="form-control" name="description" rows="2"></textarea>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Level</label>
                            <input type="number" class="form-control" name="level" min="1" max="5" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Color</label>
                            <input type="color" class="form-control" name="color" value="#6c757d" required>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary" onclick="createClassification()">Save</button>
                </div>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
    new bootstrap.Modal(modal).show();
}

async function createClassification() {
    const form = document.getElementById('classificationForm');
    const formData = new FormData(form);

    try {
        const response = await fetch('/classifications', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                name: formData.get('name'),
                description: formData.get('description'),
                level: parseInt(formData.get('level')),
                color: formData.get('color')
            })
        });

        if (response.ok) {
            const modal = document.querySelector('.modal.show');
            if (modal) bootstrap.Modal.getInstance(modal).hide();
            renderClassificationsTable();
        } else {
            const error = await response.json();
            alert('Error creating classification: ' + error.error);
        }
    } catch (error) {
        console.error('Error creating classification:', error);
        alert('Error creating classification: ' + error.message);
    }
}

async function loadSuggestions() {
    const domainParams = getDomainParams();
    const tbody = document.querySelector('#suggestionsTable tbody');
    tbody.innerHTML = '<tr><td colspan="4">Loading...</td></tr>';
    try {
        const response = await fetch(`/documents/classification-suggestions${domainParams}`);
        const suggestions = await response.json();
        tbody.innerHTML = '';
        suggestions.forEach(s => {
            const atual = s.current_classification && s.current_classification.name ? s.current_classification.name : '<span class="text-muted">None</span>';
            const atualColor = s.current_classification && s.current_classification.color ? s.current_classification.color : '#ccc';
            let sugestao = '<span class="text-muted">None</span>';
            let sugestaoColor = '#ccc';
            let motivo = '-';
            let highlight = '';
            if (s.suggested_classification) {
                sugestao = s.suggested_classification.name;
                sugestaoColor = s.suggested_classification.color || '#ccc';
                if (!s.current_classification || s.current_classification.id !== s.suggested_classification.id) {
                    highlight = 'table-warning';
                }
            }
            // Exibir motivo da sugestão (nome da regra + descrição)
            if (s.rule_name) {
                motivo = `<span class='fw-bold'>${s.rule_name}</span>`;
                if (s.rule_description) {
                    motivo += `<br><small class='text-muted'>${s.rule_description}</small>`;
                } else {
                    motivo += `<br><small class='text-muted'>Rule that motivated the suggestion.</small>`;
                }
            }
            tbody.innerHTML += `
                <tr class="${highlight}">
                    <td>${s.path}</td>
                    <td>
                        <div style="display:flex;align-items:center;gap:8px;">
                            <span class="badge" style="background:${atualColor};min-width:100px;text-align:center;font-size:1em;">${atual}</span>
                            <span class="fw-bold">→</span>
                            <span class="badge" style="background:${sugestaoColor};min-width:100px;text-align:center;font-size:1em;">${sugestao}</span>
                        </div>
                    </td>
                    <td>${motivo}</td>
                    <td style="text-align:right;vertical-align:middle;">
                        ${s.suggested_classification && (!s.current_classification || s.current_classification.id !== s.suggested_classification.id) ?
                            `<button class="btn btn-sm btn-success" onclick="applySuggestion(${s.id}, ${s.suggested_classification.id})">Apply</button>` :
                            '<span class="text-muted">-</span>'}
                    </td>
                </tr>
            `;
        });
    } catch (error) {
        tbody.innerHTML = '<tr><td colspan="4">Error loading suggestions.</td></tr>';
    }
    // Evento para aplicar todas as sugestões
    const btnAll = document.getElementById('applyAllSuggestions');
    if (btnAll) {
        btnAll.onclick = async () => {
            const response = await fetch(`/documents/classification-suggestions${domainParams}`);
            const suggestions = await response.json();
            const toApply = suggestions.filter(s => s.suggested_classification && (!s.current_classification || s.current_classification.id !== s.suggested_classification.id));
            for (const s of toApply) {
                await applySuggestion(s.id, s.suggested_classification.id, true);
            }
            loadSuggestions();
            alert('Suggestions applied!');
        };
    }
}

async function applySuggestion(documentId, classificationId, silent) {
    try {
        await fetch('/documents/classify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ document_id: documentId, classification_id: classificationId, notes: 'Auto-suggestion' })
        });
        if (!silent) {
            alert('Classification applied!');
            loadSuggestions();
        }
    } catch (error) {
        if (!silent) alert('Error applying suggestion.');
    }
}

// Funções para infraestrutura
let infrastructureGraphData = { hosts: [], users: [], shares: [], access: [] };
let infrastructureNetwork = null;

// Variáveis globais para filtros
let selectedUserType = 'all'; // 'all', 'admin', 'nonadmin'

async function loadInfrastructureData() {
    try {
        // Carregar dados
        const [hosts, users, shares, access] = await Promise.all([
            fetch('/infrastructure/hosts' + getDomainParams()).then(r => r.json()),
            fetch('/infrastructure/users' + getDomainParams()).then(r => r.json()),
            fetch('/infrastructure/shares' + getDomainParams()).then(r => r.json()),
            fetch('/infrastructure/access' + getDomainParams()).then(r => r.json())
        ]);
        infrastructureGraphData = { hosts, users, shares, access };
        updateInfrastructureStats(hosts, users, shares, access);
        renderInfrastructureFilters();
        renderInfrastructureGraph();
        setupInfrastructureFilters();
    } catch (error) {
        console.error('Error loading infrastructure data:', error);
        alert('Error loading infrastructure data. Please try again.');
    }
}

function renderInfrastructureFilters() {
    // Filtro de domínio
    const domains = Array.from(new Set([
        ...infrastructureGraphData.users.map(u => u.domain),
        ...infrastructureGraphData.hosts.map(h => h.domain)
    ])).filter(d => d && d !== '');
    const domainSelect = document.createElement('select');
    domainSelect.className = 'form-select mb-2';
    domainSelect.id = 'domainFilter';
    domainSelect.innerHTML = `<option value="all">All Domains</option>` +
        domains.map(d => `<option value="${d}">${d}</option>`).join('');
    domainSelect.value = selectedDomain;
    domainSelect.onchange = function() {
        selectedDomain = this.value;
        renderInfrastructureGraph();
    };

    // Filtro de tipo de usuário
    const userTypeSelect = document.createElement('select');
    userTypeSelect.className = 'form-select mb-2';
    userTypeSelect.id = 'userTypeFilter';
    userTypeSelect.innerHTML = `
        <option value="all">All Users</option>
        <option value="admin">Only Admins</option>
        <option value="nonadmin">Only Non-admins</option>
    `;
    userTypeSelect.value = selectedUserType;
    userTypeSelect.onchange = function() {
        selectedUserType = this.value;
        renderInfrastructureGraph();
    };

    // Inserir filtros no painel lateral
    const filtersPanel = document.querySelector('#mainContent #infrastructureFilters');
    if (filtersPanel) {
        filtersPanel.innerHTML = '';
        filtersPanel.appendChild(domainSelect);
        filtersPanel.appendChild(userTypeSelect);
    }
}

function renderInfrastructureGraph() {
    const container = document.getElementById('infrastructureGraph');
    if (!container) return;

    // Limpar conteúdo anterior
    container.innerHTML = '';

    // Filtros
    const showHosts = document.getElementById('showHosts')?.checked;
    const showUsers = document.getElementById('showUsers')?.checked;
    const showShares = document.getElementById('showShares')?.checked;
    const showRead = document.getElementById('showRead')?.checked;
    const showWrite = document.getElementById('showWrite')?.checked;
    const showAdmin = document.getElementById('showAdmin')?.checked;

    // Filtros refinados
    const domainFilter = selectedDomain;
    const userTypeFilter = selectedUserType;

    const nodes = new vis.DataSet();
    const edges = new vis.DataSet();

    // Adicionar nós de domínio
    const domains = Array.from(new Set([
        ...infrastructureGraphData.users.map(u => u.domain),
        ...infrastructureGraphData.hosts.map(h => h.domain)
    ])).filter(d => d && d !== '');
    domains.forEach(domain => {
        if (domainFilter !== 'all' && domain !== domainFilter) return;
        nodes.add({
            id: `domain_${domain}`,
            label: domain,
            group: 'domains',
            shape: 'box',
            color: '#6c757d',
            font: { color: '#fff', size: 14, face: 'Segoe UI' }
        });
    });

    // Adicionar usuários
    if (showUsers) {
        infrastructureGraphData.users.forEach(user => {
            if (domainFilter !== 'all' && user.domain !== domainFilter) return;
            if (userTypeFilter === 'admin' && !user.is_admin) return;
            if (userTypeFilter === 'nonadmin' && user.is_admin) return;
            nodes.add({
                id: `user_${user.id}`,
                label: user.username,
                group: 'users',
                title: `User: ${user.username}\nDomain: ${user.domain || 'N/A'}\nAdmin: ${user.is_admin ? 'Yes' : 'No'}`,
                color: user.is_admin ? '#dc3545' : '#28a745'
            });
            // Conectar usuário ao domínio
            if (user.domain && domains.includes(user.domain)) {
                edges.add({
                    from: `domain_${user.domain}`,
                    to: `user_${user.id}`,
                    color: '#adb5bd',
                    dashes: true,
                    label: 'member',
                    font: { align: 'middle', size: 10 }
                });
            }
        });
    }

    // Adicionar hosts
    if (showHosts) {
        infrastructureGraphData.hosts.forEach(host => {
            if (domainFilter !== 'all' && host.domain !== domainFilter) return;
            nodes.add({
                id: `host_${host.id}`,
                label: host.host,
                group: 'hosts',
                title: `Host: ${host.host}\nDomain: ${host.domain || 'N/A'}`,
                color: host.is_domain_controller ? '#dc3545' : 
                       host.is_server ? '#fd7e14' : '#17a2b8'
            });
            // Conectar host ao domínio
            if (host.domain && domains.includes(host.domain)) {
                edges.add({
                    from: `domain_${host.domain}`,
                    to: `host_${host.id}`,
                    color: '#adb5bd',
                    dashes: true,
                    label: 'member',
                    font: { align: 'middle', size: 10 }
                });
            }
        });
    }

    // Adicionar shares
    if (showShares) {
        infrastructureGraphData.shares.forEach(share => {
            if (domainFilter !== 'all' && share.domain !== domainFilter) return;
            nodes.add({
                id: `share_${share.id}`,
                label: share.name,
                group: 'shares',
                title: `Share: ${share.name}\nPath: ${share.path || 'N/A'}\nHost: ${share.host}`,
                color: share.is_accessible ? '#28a745' : '#6c757d'
            });
        });
    }

    // Conectar hosts aos shares (pertencimento)
    if (showHosts && showShares) {
        infrastructureGraphData.shares.forEach(share => {
            if (domainFilter !== 'all' && share.domain !== domainFilter) return;
            // Encontrar host correspondente
            const host = infrastructureGraphData.hosts.find(h => h.host === share.host && h.domain === share.domain);
            if (host) {
                edges.add({
                    from: `host_${host.id}`,
                    to: `share_${share.id}`,
                    arrows: 'to',
                    color: '#adb5bd',
                    dashes: true,
                    label: 'share',
                    font: { align: 'middle', size: 10 }
                });
            }
        });
    }

    // Adicionar arestas (acessos usuário → host/share)
    // Primeiro, crie um Set com user-host admin
    const userHostAdminSet = new Set();
    infrastructureGraphData.access.forEach(acc => {
        if (acc.target_type === 'host' && acc.access_type === 'admin') {
            const user = infrastructureGraphData.users.find(u => u.username === acc.username && u.domain === acc.user_domain);
            const host = infrastructureGraphData.hosts.find(h => h.host === acc.target_name && h.domain === acc.target_domain);
            if (user && host) {
                userHostAdminSet.add(`${user.id}|${host.id}`);
            }
        }
    });

    infrastructureGraphData.access.forEach(acc => {
        // Filtro de tipo de acesso
        if ((acc.access_type === 'read' && !showRead) ||
            (acc.access_type === 'write' && !showWrite) ||
            (acc.access_type === 'admin' && !showAdmin)) {
            return;
        }
        // Buscar usuário pelo nome e domínio
        const user = infrastructureGraphData.users.find(u => u.username === acc.username && u.domain === acc.user_domain);
        const sourceId = user ? `user_${user.id}` : null;
        let targetId = null;
        if (acc.target_type === 'host' && showHosts) {
            const host = infrastructureGraphData.hosts.find(h => h.host === acc.target_name && h.domain === acc.target_domain);
            if (host) targetId = `host_${host.id}`;
        } else if (acc.target_type === 'share' && showShares) {
            const share = infrastructureGraphData.shares.find(s => s.name === acc.target_name && s.domain === acc.target_domain);
            if (share) {
                // Só desenha user → share se NÃO existe user → host (admin) para o mesmo host
                const host = infrastructureGraphData.hosts.find(h => h.host === share.host && h.domain === share.domain);
                if (host && userHostAdminSet.has(`${user.id}|${host.id}`)) {
                    return; // já tem admin no host, não desenha para o share
                }
                targetId = `share_${share.id}`;
            }
        }
        // Só adiciona se ambos os nós existem e estão visíveis
        if (!sourceId || !targetId) return;
        // Destaque para admin
        const edgeColor = acc.access_type === 'admin' ? '#dc3545' : 
                          acc.access_type === 'write' ? '#fd7e14' : '#17a2b8';
        const width = acc.access_type === 'admin' ? 4 : 2;
        const dashes = acc.access_type === 'admin' ? false : true;
        edges.add({
            from: sourceId,
            to: targetId,
            label: acc.access_type,
            arrows: 'to',
            color: edgeColor,
            width: width,
            dashes: dashes,
            font: { align: 'middle', size: 10 }
        });
    });

    // Configurações do grafo
    const options = {
        nodes: {
            shape: 'dot',
            size: 16,
            font: { size: 12 }
        },
        edges: {
            font: { size: 10 },
            smooth: {
                type: 'dynamic',
                roundness: 0.4
            }
        },
        groups: {
            hosts: { shape: 'dot', size: 20 },
            users: { shape: 'dot', size: 16 },
            shares: { shape: 'dot', size: 16 }
        },
        physics: {
            stabilization: true,
            barnesHut: {
                gravitationalConstant: -2000,
                springConstant: 0.04
            }
        },
        layout: {
            improvedLayout: true,
            hierarchical: false
        },
        interaction: {
            hover: true,
            tooltipDelay: 100
        }
    };

    // Criar rede
    infrastructureNetwork = new vis.Network(container, { nodes, edges }, options);

    // Eventos de clique
    infrastructureNetwork.on('click', function(params) {
        if (params.nodes.length > 0) {
            const nodeId = params.nodes[0];
            const node = nodes.get(nodeId);
            showNodeDetails(node);
        }
    });
}

function showNodeDetails(node) {
    if (!node) return;
    let existing = document.getElementById('nodeDetailToast');
    if (existing) existing.remove();

    const toast = document.createElement('div');
    toast.id = 'nodeDetailToast';
    toast.style.cssText = 'position:fixed;bottom:20px;right:20px;z-index:9999;min-width:260px;';
    toast.innerHTML = `
        <div class="card shadow">
            <div class="card-header d-flex justify-content-between align-items-center" style="background:var(--secondary-color);color:white;">
                <strong>${node.group ? node.group.charAt(0).toUpperCase() + node.group.slice(1) : 'Node'}</strong>
                <button type="button" class="btn-close btn-close-white btn-sm" onclick="this.closest('#nodeDetailToast').remove()"></button>
            </div>
            <div class="card-body">
                <p class="mb-1"><strong>Label:</strong> ${node.label || '-'}</p>
                ${node.title ? `<p class="mb-0 text-muted" style="font-size:0.85em;white-space:pre-line;">${node.title}</p>` : ''}
            </div>
        </div>
    `;
    document.body.appendChild(toast);
}

async function populateInfrastructure() {
    try {
        const response = await fetch('/infrastructure/populate', {
            method: 'POST'
        });
        
        if (response.ok) {
            alert('Infrastructure data updated successfully!');
            loadInfrastructureData();
        } else {
            const error = await response.json();
            alert('Error updating data: ' + error.error);
        }
    } catch (error) {
        console.error('Error updating infrastructure:', error);
        alert('Error updating infrastructure data.');
    }
}

function updateInfrastructureStats(hosts, users, shares, access) {
    const stats = document.getElementById('infrastructureStats');
    if (!stats) return;

    const adminUsers = users.filter(u => u.is_admin).length;
    const accessibleShares = shares.filter(s => s.is_accessible).length;

    // Lógica para acessos únicos relevantes
    // 1. Set para user-host admin
    const userHostAdminSet = new Set();
    access.forEach(acc => {
        if (acc.target_type === 'host' && acc.access_type === 'admin') {
            userHostAdminSet.add(`${acc.username}|${acc.target_name}`);
        }
    });
    // 2. Contar acessos a hosts
    const hostAccesses = access.filter(acc => acc.target_type === 'host');
    // 3. Contar acessos a shares, removendo duplicidade admin
    const shareAccesses = access.filter(acc => {
        if (acc.target_type !== 'share') return false;
        // Só conta se NÃO existe admin no host correspondente
        const shareHost = hosts.find(h => h.host === acc.target_domain);
        if (shareHost && userHostAdminSet.has(`${acc.username}|${shareHost.host}`) && acc.access_type === 'admin') {
            return false;
        }
        return true;
    });
    // 4. Contagem final
    const totalAccesses = hostAccesses.length + shareAccesses.length;
    const adminAccesses = hostAccesses.filter(a => a.access_type === 'admin').length + shareAccesses.filter(a => a.access_type === 'admin').length;

    stats.innerHTML = `
        <div class="mb-3">
            <h6>Hosts</h6>
            <p class="mb-0">Total: ${hosts.length}</p>
            <p class="mb-0">Servers: ${hosts.filter(h => h.is_server).length}</p>
            <p class="mb-0">Workstations: ${hosts.filter(h => h.is_workstation).length}</p>
        </div>
        <div class="mb-3">
            <h6>Users</h6>
            <p class="mb-0">Total: ${users.length}</p>
            <p class="mb-0">Admins: ${adminUsers}</p>
        </div>
        <div class="mb-3">
            <h6>Shares</h6>
            <p class="mb-0">Total: ${shares.length}</p>
            <p class="mb-0">Accessible: ${accessibleShares}</p>
        </div>
        <div>
            <h6>Access</h6>
            <p class="mb-0">Total: ${totalAccesses}</p>
            <p class="mb-0">Admin: ${adminAccesses}</p>
        </div>
    `;
}

function setupInfrastructureFilters() {
    const filters = [
        'showHosts', 'showUsers', 'showShares',
        'showRead', 'showWrite', 'showAdmin'
    ];
    filters.forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el.onchange = () => renderInfrastructureGraph();
        }
    });
}