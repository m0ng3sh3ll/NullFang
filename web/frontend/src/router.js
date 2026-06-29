// Variáveis globais
let selectedDomain = '';
let availableDomains = [];
let allDocuments = [];
let currentPage = 0;
const PAGE_SIZE = 50;

function showToast(message, type) {
    type = type || 'success';
    let container = document.getElementById('toastContainer');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toastContainer';
        container.style.cssText = 'position:fixed;top:20px;right:20px;z-index:11000;display:flex;flex-direction:column;gap:8px;pointer-events:none;';
        document.body.appendChild(container);
    }
    const toast = document.createElement('div');
    const bg = type === 'error' ? '#dc3545' : type === 'warning' ? '#ffc107' : type === 'info' ? '#17a2b8' : '#28a745';
    const textColor = type === 'warning' ? '#000' : '#fff';
    toast.style.cssText = `background:${bg};color:${textColor};padding:12px 16px;border-radius:6px;box-shadow:0 4px 12px rgba(0,0,0,.3);min-width:240px;max-width:380px;display:flex;justify-content:space-between;align-items:center;pointer-events:auto;font-size:0.9em;`;
    toast.innerHTML = `<span>${message}</span><button onclick="this.parentElement.remove()" style="background:none;border:none;color:inherit;font-size:1.2em;cursor:pointer;margin-left:12px;line-height:1;">×</button>`;
    container.appendChild(toast);
    setTimeout(() => { if (toast.parentElement) toast.remove(); }, 4000);
}

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

function getDomainBadge() {
    if (!selectedDomain) return '';
    return `<span class="badge ms-2" style="background:#34495e;font-size:0.75rem;font-weight:400;vertical-align:middle;">
        ${selectedDomain} <span onclick="updateSelectedDomain('');document.getElementById('domainSelector').value='';loadContent(window.location.pathname);" style="cursor:pointer;opacity:0.7;margin-left:4px;">✕</span>
    </span>`;
}

// Rotas da aplicação
const routes = {
    '/': 'triage',
    '/triage': 'triage',
    '/classify': 'classify',
    '/documents': 'triage',
    '/analysis': 'analysis',
    '/settings': 'classify',
    '/suggestions': 'triage',
    '/infrastructure': 'infrastructure',
    '/report': 'analysis'
};

// Função para navegação
function navigate(route) {
    history.pushState(null, '', route);
    loadContent(route);
    // Active nav link
    document.querySelectorAll('#mainNav .nav-link').forEach(el => {
        const href = el.getAttribute('onclick') || '';
        el.classList.toggle('active', href.includes(`'${route}'`));
    });
}

// Função para carregar conteúdo
function loadContent(route) {
    const mainContent = document.getElementById('mainContent');
    if (!mainContent) return;

    switch (route) {
        case '/':
        case '/documents':
        case '/suggestions':
            navigate('/triage');
            return;

        case '/settings':
            navigate('/classify');
            return;

        case '/report':
            navigate('/analysis');
            return;

        case '/triage':
            mainContent.innerHTML = `
                <div class="container-fluid mt-4" style="max-width:1400px;">
                    <div class="d-flex justify-content-between align-items-center mb-3">
                        <h2 class="mb-0">Triage <small id="triageDomainBadge"></small></h2>
                        <div class="d-flex gap-2">
                            <button class="btn btn-success btn-sm" onclick="applyAllSuggestionsInline()">
                                <i class="bi bi-check-all me-1"></i>Apply All Suggestions
                            </button>
                            <button class="btn btn-primary btn-sm" onclick="bulkClassifySelected()">
                                Classify Selected
                            </button>
                        </div>
                    </div>

                    <div class="card mb-3">
                        <div class="card-body py-2">
                            <div class="row g-2 align-items-center">
                                <div class="col-md-4">
                                    <input type="text" id="triageSearch" class="form-control form-control-sm" placeholder="Search by name or path…" oninput="filterTriage()">
                                </div>
                                <div class="col-md-3">
                                    <input type="text" id="triageHostFilter" class="form-control form-control-sm" placeholder="Filter by host…" oninput="filterTriage()">
                                </div>
                                <div class="col-md-3">
                                    <select id="triageClassFilter" class="form-select form-select-sm" onchange="filterTriage()">
                                        <option value="">All classifications</option>
                                        <option value="__unclassified__">Unclassified only</option>
                                    </select>
                                </div>
                                <div class="col-md-2 text-end">
                                    <button class="btn btn-outline-secondary btn-sm" onclick="clearTriageFilters()">Clear</button>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="card">
                        <div class="card-body p-0">
                            <div class="table-responsive">
                                <table class="table table-sm table-hover mb-0" id="triageTable">
                                    <thead>
                                        <tr>
                                            <th style="width:32px;"><input type="checkbox" id="triageSelectAll" onchange="toggleTriageSelectAll(this)"></th>
                                            <th>File</th>
                                            <th>Host</th>
                                            <th>Share</th>
                                            <th>Pattern</th>
                                            <th>Suggestion</th>
                                            <th>Classification</th>
                                            <th style="width:110px;">Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody id="triageTableBody">
                                        <tr><td colspan="8" class="text-center py-4"><div class="spinner-border spinner-border-sm me-2"></div>Loading…</td></tr>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>

                    <div class="d-flex justify-content-between align-items-center mt-3" id="triagePagination"></div>
                </div>
            `;
            document.getElementById('triageDomainBadge').innerHTML = getDomainBadge();
            populateTriageClassFilter();
            loadTriage();
            break;

        case '/classify':
            mainContent.innerHTML = `
                <div class="container mt-4">
                    <h2>Classify</h2>
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

        case '/analysis':
            mainContent.innerHTML = `
                <div class="container-fluid mt-4" style="max-width:1200px;">
                    <div class="d-flex justify-content-between align-items-center mb-4">
                        <div>
                            <h2 class="mb-0">Findings Analysis</h2>
                            <small class="text-muted" id="analysisDate"></small>
                        </div>
                        <button class="btn btn-outline-secondary btn-sm" onclick="copyAnalysisSummary()">
                            <i class="bi bi-clipboard me-1"></i>Copy Summary
                        </button>
                    </div>

                    <!-- Stat cards -->
                    <div class="row g-3 mb-4">
                        <div class="col-6 col-md-3">
                            <div class="card text-center">
                                <div class="card-body py-3">
                                    <div class="display-6 fw-bold text-dark" id="statTotalFiles">—</div>
                                    <div class="text-muted" style="font-size:0.78rem;text-transform:uppercase;letter-spacing:.06em;">Files Found</div>
                                </div>
                            </div>
                        </div>
                        <div class="col-6 col-md-3">
                            <div class="card text-center">
                                <div class="card-body py-3">
                                    <div class="display-6 fw-bold text-dark" id="statClassified">—</div>
                                    <div class="text-muted" style="font-size:0.78rem;text-transform:uppercase;letter-spacing:.06em;">Classified</div>
                                </div>
                            </div>
                        </div>
                        <div class="col-6 col-md-3">
                            <div class="card text-center">
                                <div class="card-body py-3">
                                    <div class="display-6 fw-bold" id="statCritical" style="color:#dc3545;">—</div>
                                    <div class="text-muted" style="font-size:0.78rem;text-transform:uppercase;letter-spacing:.06em;">Critical</div>
                                </div>
                            </div>
                        </div>
                        <div class="col-6 col-md-3">
                            <div class="card text-center">
                                <div class="card-body py-3">
                                    <div class="display-6 fw-bold" id="statHosts" style="color:#17a2b8;">—</div>
                                    <div class="text-muted" style="font-size:0.78rem;text-transform:uppercase;letter-spacing:.06em;">Hosts</div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Pie + breakdown table -->
                    <div class="row g-3 mb-4">
                        <div class="col-md-5">
                            <div class="card h-100">
                                <div class="card-header"><h6 class="mb-0">Distribution by Classification</h6></div>
                                <div class="card-body d-flex align-items-center justify-content-center">
                                    <canvas id="classPieChart" style="max-height:240px;"></canvas>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-7">
                            <div class="card h-100">
                                <div class="card-header"><h6 class="mb-0">Breakdown</h6></div>
                                <div class="card-body">
                                    <table class="table table-sm mb-2" id="classSummaryTable">
                                        <thead>
                                            <tr>
                                                <th>Classification</th>
                                                <th class="text-end">Files</th>
                                                <th class="text-end">%</th>
                                            </tr>
                                        </thead>
                                        <tbody></tbody>
                                    </table>
                                    <div id="classificationTotals" class="text-muted" style="font-size:0.82rem;border-top:1px solid #dee2e6;padding-top:8px;"></div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Bottom charts -->
                    <div class="row g-3">
                        <div class="col-md-6">
                            <div class="card">
                                <div class="card-header"><h6 class="mb-0">Top Patterns Found</h6></div>
                                <div class="card-body">
                                    <canvas id="patternBarChart" style="max-height:220px;"></canvas>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="card">
                                <div class="card-header"><h6 class="mb-0">Top Hosts by Files Found</h6></div>
                                <div class="card-body">
                                    <canvas id="hostBarChart" style="max-height:220px;"></canvas>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            loadAnalysisCharts();
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
            navigate('/triage');
            return;
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
    currentPage = 0;
    const domainParams = getDomainParams();
    fetch(`/documents${domainParams}`)
        .then(response => response.json())
        .then(documents => {
            allDocuments = documents || [];
            renderDocumentsPage();
        })
        .catch(error => {
            console.error('Error loading documents:', error);
            showToast('Error loading documents. Please try again.', 'error');
            const tbody = document.querySelector('#documentsTable tbody');
            if (tbody) tbody.innerHTML = '<tr><td colspan="13" class="text-center text-danger">Error loading documents.</td></tr>';
        });
}

function renderDocumentsPage() {
    const tbody = document.querySelector('#documentsTable tbody');
    if (!tbody) return;

    const start = currentPage * PAGE_SIZE;
    const end = Math.min(start + PAGE_SIZE, allDocuments.length);
    const pageDocuments = allDocuments.slice(start, end);

    tbody.innerHTML = '';
    pageDocuments.forEach(doc => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><input type="checkbox" class="document-checkbox" data-id="${doc.id}"></td>
            <td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${doc.name || ''}">${doc.name || ''}</td>
            <td>${doc.host || ''}</td>
            <td>${doc.share || ''}</td>
            <td>${doc.domain || ''}</td>
            <td>${formatSize(doc.size)}</td>
            <td>${doc.last_modified ? new Date(doc.last_modified).toLocaleDateString() : ''}</td>
            <td>${doc.search_param_type || ''}</td>
            <td>${doc.search_param_value || ''}</td>
            <td>${doc.match_pattern || ''}</td>
            <td>${doc.match_type || ''}</td>
            <td>
                ${doc.classification ?
                    `<span class="badge" style="background-color: ${doc.classification.color}">${doc.classification.name}</span>`
                    : '<span class="badge bg-secondary">Unclassified</span>'}
            </td>
            <td>
                <button class="btn btn-sm btn-primary" onclick="classifyDocument(${doc.id})">Classify</button>
            </td>
        `;
        tbody.appendChild(tr);
    });

    updateDocumentsPagination();

    const selectAllCheckbox = document.querySelector('#selectAll');
    if (selectAllCheckbox) {
        selectAllCheckbox.addEventListener('change', function() {
            document.querySelectorAll('.document-checkbox').forEach(cb => { cb.checked = this.checked; });
        });
    }
}

function updateDocumentsPagination() {
    const paginationDiv = document.getElementById('documentsPagination');
    if (!paginationDiv) return;

    const totalPages = Math.ceil(allDocuments.length / PAGE_SIZE);
    if (totalPages <= 1) {
        paginationDiv.innerHTML = `<small class="text-muted">${allDocuments.length} files</small>`;
        return;
    }

    const maxButtons = 7;
    let startPage = Math.max(0, currentPage - Math.floor(maxButtons / 2));
    let endPage = Math.min(totalPages, startPage + maxButtons);
    if (endPage - startPage < maxButtons) startPage = Math.max(0, endPage - maxButtons);

    let buttons = '';
    for (let i = startPage; i < endPage; i++) {
        buttons += `<li class="page-item ${i === currentPage ? 'active' : ''}">
            <button class="page-link" onclick="changePage(${i})">${i + 1}</button></li>`;
    }

    paginationDiv.innerHTML = `
        <nav><ul class="pagination pagination-sm mb-0">
            <li class="page-item ${currentPage === 0 ? 'disabled' : ''}">
                <button class="page-link" onclick="changePage(${currentPage - 1})">«</button></li>
            ${buttons}
            <li class="page-item ${currentPage >= totalPages - 1 ? 'disabled' : ''}">
                <button class="page-link" onclick="changePage(${currentPage + 1})">»</button></li>
        </ul></nav>
        <small class="text-muted">${currentPage * PAGE_SIZE + 1}–${Math.min((currentPage + 1) * PAGE_SIZE, allDocuments.length)} of ${allDocuments.length}</small>
    `;
}

function changePage(page) {
    const totalPages = Math.ceil(allDocuments.length / PAGE_SIZE);
    if (page < 0 || page >= totalPages) return;
    currentPage = page;
    renderDocumentsPage();
    document.querySelector('#documentsTable')?.scrollIntoView({ behavior: 'smooth' });
}

// ——— Triage state ———
let triageAllDocuments = [];
let triageSuggestionsMap = {};
let triageFiltered = [];
let triagePage = 0;
const TRIAGE_PAGE_SIZE = 50;
let _triageBulkIds = [];

async function populateTriageClassFilter() {
    try {
        const res = await fetch('/classifications');
        const classes = await res.json();
        const sel = document.getElementById('triageClassFilter');
        if (!sel) return;
        classes.forEach(c => {
            const opt = document.createElement('option');
            opt.value = c.id;
            opt.textContent = c.name;
            sel.appendChild(opt);
        });
    } catch(e) {}
}

async function loadTriage() {
    const domainParams = getDomainParams();
    const tbody = document.getElementById('triageTableBody');
    if (tbody) tbody.innerHTML = '<tr><td colspan="8" class="text-center py-4"><div class="spinner-border spinner-border-sm me-2"></div>Loading…</td></tr>';
    try {
        const [docs, suggestions] = await Promise.all([
            fetch(`/documents${domainParams}`).then(r => r.json()),
            fetch(`/documents/classification-suggestions${domainParams}`).then(r => r.json()).catch(() => [])
        ]);

        triageAllDocuments = docs || [];
        triageSuggestionsMap = {};
        (suggestions || []).forEach(s => {
            const fid = s.id || s.file_id;
            if (fid && !triageSuggestionsMap[fid]) {
                triageSuggestionsMap[fid] = s;
            }
        });

        filterTriage();
    } catch(err) {
        console.error('Triage load error:', err);
        showToast('Error loading triage data.', 'error');
    }
}

function filterTriage() {
    const search = (document.getElementById('triageSearch')?.value || '').toLowerCase();
    const hostFilter = (document.getElementById('triageHostFilter')?.value || '').toLowerCase();
    const classFilter = document.getElementById('triageClassFilter')?.value || '';

    triageFiltered = triageAllDocuments.filter(doc => {
        if (search && !(doc.name || '').toLowerCase().includes(search) && !(doc.path || '').toLowerCase().includes(search)) return false;
        if (hostFilter && !(doc.host || '').toLowerCase().includes(hostFilter)) return false;
        if (classFilter === '__unclassified__' && doc.classification) return false;
        if (classFilter && classFilter !== '__unclassified__' && doc.classification?.id != classFilter) return false;
        return true;
    });

    triagePage = 0;
    renderTriagePage();
}

function clearTriageFilters() {
    const s = document.getElementById('triageSearch'); if (s) s.value = '';
    const h = document.getElementById('triageHostFilter'); if (h) h.value = '';
    const c = document.getElementById('triageClassFilter'); if (c) c.value = '';
    filterTriage();
}

function renderTriagePage() {
    const tbody = document.getElementById('triageTableBody');
    if (!tbody) return;

    const start = triagePage * TRIAGE_PAGE_SIZE;
    const pageItems = triageFiltered.slice(start, start + TRIAGE_PAGE_SIZE);

    if (pageItems.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" class="text-center text-muted py-4">${
            triageAllDocuments.length === 0
                ? 'No files found. Run a scan first.'
                : 'No files match the current filters.'
        }</td></tr>`;
    } else {
        tbody.innerHTML = pageItems.map(doc => {
            const sugg = triageSuggestionsMap[doc.id];
            let suggColor = '#6c757d';
            let suggName = '?';
            let suggClassId = '';
            if (sugg) {
                const sc = sugg.suggested_classification;
                if (sc) {
                    suggColor = sc.color || '#6c757d';
                    suggName = sc.name || '?';
                    suggClassId = sc.id || '';
                }
            }
            const suggBadge = sugg && suggClassId
                ? `<span class="badge" style="background:${suggColor};cursor:pointer;" onclick="applySuggestionDirect(${doc.id},${suggClassId})" title="Click to apply: ${sugg.rule_name || ''}">${suggName} ↵</span>`
                : `<span class="text-muted small">—</span>`;
            const classBadge = doc.classification
                ? `<span class="badge" style="background:${doc.classification.color}">${doc.classification.name}</span>`
                : `<span class="text-muted small">—</span>`;
            const fileName = (doc.name || doc.path || '').split(/[/\\]/).pop();
            return `<tr>
                <td><input type="checkbox" class="triage-cb" data-id="${doc.id}"></td>
                <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${doc.path || doc.name || ''}">${fileName}</td>
                <td>${doc.host || ''}</td>
                <td>${doc.share || ''}</td>
                <td style="max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${doc.match_pattern || ''}">${doc.match_pattern || ''}</td>
                <td>${suggBadge}</td>
                <td>${classBadge}</td>
                <td>
                    <button class="btn btn-sm btn-outline-primary" style="font-size:0.75rem;padding:2px 8px;" onclick="showClassifyModal(${doc.id})">Classify</button>
                </td>
            </tr>`;
        }).join('');
    }

    const totalPages = Math.ceil(triageFiltered.length / TRIAGE_PAGE_SIZE);
    const pag = document.getElementById('triagePagination');
    if (pag) {
        pag.innerHTML = `
            <small class="text-muted">${triageFiltered.length} files — page ${triagePage + 1} of ${Math.max(1, totalPages)}</small>
            <div class="btn-group btn-group-sm">
                <button class="btn btn-outline-secondary" onclick="changeTriagePage(${triagePage - 1})" ${triagePage === 0 ? 'disabled' : ''}>← Prev</button>
                <button class="btn btn-outline-secondary" onclick="changeTriagePage(${triagePage + 1})" ${triagePage >= totalPages - 1 ? 'disabled' : ''}>Next →</button>
            </div>
        `;
    }
    const allCb = document.getElementById('triageSelectAll');
    if (allCb) allCb.checked = false;
}

function changeTriagePage(page) {
    const totalPages = Math.ceil(triageFiltered.length / TRIAGE_PAGE_SIZE);
    if (page < 0 || page >= totalPages) return;
    triagePage = page;
    renderTriagePage();
}

function toggleTriageSelectAll(cb) {
    document.querySelectorAll('.triage-cb').forEach(el => el.checked = cb.checked);
}

async function applySuggestionDirect(fileId, classificationId) {
    try {
        const res = await fetch('/documents/classify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ document_id: fileId, classification_id: parseInt(classificationId), notes: 'Auto-suggestion' })
        });
        if (!res.ok) throw new Error('Classification failed');
        const doc = triageAllDocuments.find(d => d.id === fileId);
        if (doc && triageSuggestionsMap[fileId]) {
            const sc = triageSuggestionsMap[fileId].suggested_classification;
            doc.classification = sc ? { id: sc.id, name: sc.name, color: sc.color } : null;
            delete triageSuggestionsMap[fileId];
        }
        filterTriage();
        showToast('Classification applied.', 'success');
    } catch(e) {
        showToast('Error applying classification.', 'error');
    }
}

async function applyAllSuggestionsInline() {
    const entries = Object.entries(triageSuggestionsMap);
    const toApply = entries.filter(([fid, s]) => {
        const sc = s.suggested_classification;
        const doc = triageAllDocuments.find(d => d.id == fid);
        return sc && (!doc?.classification || doc.classification.id !== sc.id);
    });
    if (toApply.length === 0) { showToast('No pending suggestions.', 'info'); return; }
    if (!confirm(`Apply ${toApply.length} suggestions?`)) return;
    let applied = 0;
    for (const [fid, s] of toApply) {
        try {
            const sc = s.suggested_classification;
            await fetch('/documents/classify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ document_id: parseInt(fid), classification_id: sc.id, notes: 'Auto-suggestion' })
            });
            const doc = triageAllDocuments.find(d => d.id == fid);
            if (doc) doc.classification = { id: sc.id, name: sc.name, color: sc.color };
            delete triageSuggestionsMap[fid];
            applied++;
        } catch(e) {}
    }
    filterTriage();
    showToast(`Applied ${applied} suggestions.`, 'success');
}

async function showBulkClassifyModal(ids) {
    _triageBulkIds = ids;
    try {
        const res = await fetch('/classifications');
        const classifications = await res.json();
        const modal = document.createElement('div');
        modal.className = 'modal fade';
        modal.innerHTML = `
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Classify ${ids.length} File(s)</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <label class="form-label">Classification</label>
                            <select class="form-select" id="triageBulkClassSelect">
                                <option value="">Select a classification</option>
                                ${classifications.map(c => `<option value="${c.id}">${c.name}</option>`).join('')}
                            </select>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="button" class="btn btn-primary" onclick="submitTriageBulkClassify()">Classify</button>
                    </div>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
        new bootstrap.Modal(modal).show();
    } catch(e) {
        showToast('Error loading classifications.', 'error');
    }
}

async function submitTriageBulkClassify() {
    const classificationId = parseInt(document.getElementById('triageBulkClassSelect')?.value);
    if (!classificationId) { showToast('Select a classification.', 'warning'); return; }
    const ids = _triageBulkIds;
    if (!ids.length) return;
    try {
        const res = await fetch('/documents/bulk-classify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ document_ids: ids, classification_id: classificationId })
        });
        if (!res.ok) throw new Error();
        const modal = document.querySelector('.modal.show');
        if (modal) { bootstrap.Modal.getInstance(modal).hide(); modal.remove(); }
        showToast(`${ids.length} files classified.`, 'success');
        loadTriage();
    } catch(e) {
        showToast('Error classifying files.', 'error');
    }
}

function bulkClassifySelected() {
    const checked = [...document.querySelectorAll('.triage-cb:checked')].map(cb => parseInt(cb.dataset.id));
    if (checked.length === 0) { showToast('Select files first.', 'warning'); return; }
    showBulkClassifyModal(checked);
}

// Stores the last loaded analysis data for copyAnalysisSummary()
let _analysisSnapshot = null;

function destroyChart(canvasId) {
    const existing = Chart.getChart(canvasId);
    if (existing) existing.destroy();
}

async function loadAnalysisCharts() {
    const domainParams = getDomainParams();
    const dateSpan = document.getElementById('analysisDate');
    if (dateSpan) dateSpan.textContent = 'Loading...';

    try {
        const [stats, summary] = await Promise.all([
            fetch(`/analysis/stats${domainParams}`).then(async r => {
                if (!r.ok) throw new Error(`/analysis/stats HTTP ${r.status}: ${await r.text()}`);
                return r.json();
            }),
            fetch(`/analysis/summary${domainParams}`).then(async r => {
                if (!r.ok) throw new Error(`/analysis/summary HTTP ${r.status}: ${await r.text()}`);
                return r.json();
            }),
        ]);

        _analysisSnapshot = { stats, summary };

        // Stat cards
        const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
        set('statTotalFiles', summary.total_files ?? 0);
        const classifiedPct = summary.total_files ? Math.round((summary.classified_files / summary.total_files) * 100) : 0;
        set('statClassified', `${summary.classified_files ?? 0} (${classifiedPct}%)`);
        set('statCritical', summary.critical_files ?? 0);
        set('statHosts', summary.total_hosts ?? 0);

        // Pie chart
        destroyChart('classPieChart');
        const pieCtx = document.getElementById('classPieChart')?.getContext('2d');
        if (pieCtx && stats.length > 0) {
            new Chart(pieCtx, {
                type: 'doughnut',
                data: {
                    labels: stats.map(s => s.name),
                    datasets: [{ data: stats.map(s => s.document_count), backgroundColor: stats.map(s => s.color), borderWidth: 2, borderColor: '#161b22' }]
                },
                options: {
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: { padding: 14, font: { size: 12 }, color: '#8b949e' }
                        }
                    },
                    cutout: '58%'
                }
            });
        }

        // Breakdown table
        const total = stats.reduce((s, c) => s + c.document_count, 0);
        const tbody = document.querySelector('#classSummaryTable tbody');
        if (tbody) {
            tbody.innerHTML = stats.map(s => `
                <tr>
                    <td><span class="badge" style="background:${s.color};">${s.name}</span></td>
                    <td class="text-end fw-bold">${s.document_count}</td>
                    <td class="text-end text-muted">${total ? ((s.document_count / total) * 100).toFixed(1) : 0}%</td>
                </tr>
            `).join('');
        }
        const totalsEl = document.getElementById('classificationTotals');
        if (totalsEl) {
            const unclassified = (summary.total_files ?? 0) - (summary.classified_files ?? 0);
            totalsEl.innerHTML = `<strong>${total}</strong> classified &nbsp;·&nbsp; <strong>${unclassified}</strong> unclassified &nbsp;·&nbsp; <strong>${summary.total_files ?? 0}</strong> total`;
        }

        // Top patterns bar chart (horizontal)
        const patterns = summary.top_patterns || [];
        destroyChart('patternBarChart');
        const patCtx = document.getElementById('patternBarChart')?.getContext('2d');
        const darkScales = {
            x: { beginAtZero: true, ticks: { precision: 0, color: '#8b949e', font: { size: 11 } }, grid: { color: '#21262d' } },
            y: { ticks: { color: '#8b949e', font: { size: 11 } }, grid: { color: '#21262d' } }
        };

        if (patCtx && patterns.length > 0) {
            new Chart(patCtx, {
                type: 'bar',
                data: {
                    labels: patterns.map(p => p.pattern.length > 30 ? p.pattern.slice(0, 28) + '…' : p.pattern),
                    datasets: [{ data: patterns.map(p => p.count), backgroundColor: '#fd7e14', borderRadius: 4, borderSkipped: false }]
                },
                options: {
                    indexAxis: 'y',
                    plugins: { legend: { display: false } },
                    scales: darkScales
                }
            });
        } else if (patCtx) {
            document.getElementById('patternBarChart').parentElement.innerHTML += '<p class="text-muted small text-center mt-3">No pattern data — run a scan with <code>-m</code> or <code>-r</code>.</p>';
        }

        const hosts = summary.top_hosts || [];
        destroyChart('hostBarChart');
        const hostCtx = document.getElementById('hostBarChart')?.getContext('2d');
        if (hostCtx && hosts.length > 0) {
            new Chart(hostCtx, {
                type: 'bar',
                data: {
                    labels: hosts.map(h => h.host),
                    datasets: [{ data: hosts.map(h => h.count), backgroundColor: '#58a6ff', borderRadius: 4, borderSkipped: false }]
                },
                options: {
                    indexAxis: 'y',
                    plugins: { legend: { display: false } },
                    scales: darkScales
                }
            });
        } else if (hostCtx) {
            document.getElementById('hostBarChart').parentElement.innerHTML += '<p class="text-muted small text-center mt-3">No host data yet.</p>';
        }

        if (dateSpan) dateSpan.textContent = `Generated ${new Date().toLocaleString()}`;

    } catch (err) {
        console.error('Error loading analysis:', err);
        showToast('Analysis error: ' + (err.message || err), 'error');
    }
}

function copyAnalysisSummary() {
    const d = _analysisSnapshot;
    if (!d) { showToast('Load analysis first.', 'warning'); return; }
    const { stats, summary } = d;
    const total = stats.reduce((s, c) => s + c.document_count, 0);
    const unclassified = (summary.total_files ?? 0) - (summary.classified_files ?? 0);
    const pct = summary.total_files ? ((summary.classified_files / summary.total_files) * 100).toFixed(1) : 0;

    let text = `NullFang Findings Summary — ${new Date().toLocaleString()}\n`;
    text += `${'─'.repeat(48)}\n\n`;
    text += `Files Found:   ${summary.total_files ?? 0} across ${summary.total_hosts ?? 0} hosts\n`;
    text += `Classified:    ${summary.classified_files ?? 0} of ${summary.total_files ?? 0} (${pct}%)\n\n`;
    text += `Classifications:\n`;
    stats.forEach(s => {
        const p = total ? ((s.document_count / total) * 100).toFixed(1) : '0.0';
        text += `  ${s.name.padEnd(16)} ${String(s.document_count).padStart(5)} files  (${p}%)\n`;
    });
    text += `  ${'─'.repeat(32)}\n`;
    text += `  ${'Unclassified'.padEnd(16)} ${String(unclassified).padStart(5)} files\n`;

    const patterns = summary.top_patterns || [];
    if (patterns.length > 0) {
        text += `\nTop Patterns Found:\n`;
        patterns.forEach(p => { text += `  ${p.pattern.padEnd(30)} ${p.count} files\n`; });
    }
    const hosts = summary.top_hosts || [];
    if (hosts.length > 0) {
        text += `\nTop Hosts by Files Found:\n`;
        hosts.forEach(h => { text += `  ${h.host.padEnd(30)} ${h.count} files\n`; });
    }

    navigator.clipboard.writeText(text)
        .then(() => showToast('Summary copied to clipboard.', 'success'))
        .catch(() => showToast('Copy failed — check clipboard permissions.', 'error'));
}

function loadClassifications() {
    fetch('/classifications')
        .then(response => {
            if (!response.ok) throw new Error('Error loading classifications');
            return response.json();
        })
        .then(classifications => {
            const select = document.getElementById('classificationSelect');
            if (!select) return;
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
            showToast('Error loading classifications.', 'error');
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
            const createModal = document.querySelector('.modal:not([data-rule-edit])');
            if (createModal) {
                bootstrap.Modal.getInstance(createModal).hide();
                createModal.remove();
            }
            showToast('Rule created successfully.');
        } else {
            const error = await response.json();
            showToast('Error creating rule: ' + error.error, 'error');
        }
    } catch (error) {
        console.error('Error creating rule:', error);
        showToast('Error creating rule: ' + error.message, 'error');
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
        showToast('Error loading rule for editing.', 'error');
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
            const editModal = document.querySelector('.modal[data-rule-edit]');
            if (editModal) {
                bootstrap.Modal.getInstance(editModal).hide();
                editModal.remove();
            }
            showToast('Rule updated successfully.');
        } else {
            const error = await response.json();
            showToast('Error updating rule: ' + error.error, 'error');
        }
    } catch (error) {
        console.error('Error updating rule:', error);
        showToast('Error updating rule: ' + error.message, 'error');
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
            showToast('Rule deleted.');
        } else {
            const error = await response.json();
            showToast('Error deleting rule: ' + error.error, 'error');
        }
    } catch (error) {
        console.error('Error deleting rule:', error);
        showToast('Error deleting rule.', 'error');
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
    navigate('/triage');

    // Adicione outras funções usadas em onclick conforme necessário
    window.navigate = navigate;
    window.populateInfrastructure = populateInfrastructure;
    window.classifySelected = classifySelected;
    window.autoClassifyDocuments = autoClassifyDocuments;
    window.applyClassification = applyClassification;
    window.showNewClassificationModal = showNewClassificationModal;
    window.showNewRuleModal = showNewRuleModal;
    window.createClassification = createClassification;
    window.changePage = changePage;
    window.copyAnalysisSummary = copyAnalysisSummary;
    window.downloadReport = downloadReport;
    window.editRule = editRule;
    window.updateRule = updateRule;
    window.deleteRule = deleteRule;
    window.applySuggestion = applySuggestion;
    // Triage functions
    window.loadTriage = loadTriage;
    window.filterTriage = filterTriage;
    window.clearTriageFilters = clearTriageFilters;
    window.changeTriagePage = changeTriagePage;
    window.toggleTriageSelectAll = toggleTriageSelectAll;
    window.applySuggestionDirect = applySuggestionDirect;
    window.applyAllSuggestionsInline = applyAllSuggestionsInline;
    window.bulkClassifySelected = bulkClassifySelected;
    window.showBulkClassifyModal = showBulkClassifyModal;
    window.submitTriageBulkClassify = submitTriageBulkClassify;
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
        showToast('Please select at least one document to classify.', 'warning');
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
            showToast('Documents classified successfully!');
            loadDocuments();
            const modal = bootstrap.Modal.getInstance(document.getElementById('classificationModal'));
            if (modal) modal.hide();
            document.getElementById('classificationSelect').value = '';
            document.getElementById('classificationNotes').value = '';
        })
        .catch(error => {
            console.error('Error classifying documents:', error);
            showToast('Error classifying documents. Please try again.', 'error');
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
            showToast('Classification created.');
        } else {
            const error = await response.json();
            showToast('Error creating classification: ' + error.error, 'error');
        }
    } catch (error) {
        console.error('Error creating classification:', error);
        showToast('Error creating classification: ' + error.message, 'error');
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
            showToast(`${toApply.length} suggestion(s) applied!`);
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
            showToast('Classification applied!');
            loadSuggestions();
        }
    } catch (error) {
        if (!silent) showToast('Error applying suggestion.', 'error');
    }
}

// Funções para infraestrutura
let infrastructureGraphData = { hosts: [], users: [], shares: [], access: [] };
let infrastructureNetwork = null;

// Variáveis globais para filtros
let selectedUserType = 'all'; // 'all', 'admin', 'nonadmin'

async function loadInfrastructureData(skipAutoPopulate = false) {
    const container = document.getElementById('infrastructureGraph');
    if (container) container.innerHTML = '<div class="d-flex justify-content-center align-items-center h-100"><div class="spinner-border text-primary me-2"></div><span>Loading infrastructure data...</span></div>';
    try {
        const [hosts, users, shares, access] = await Promise.all([
            fetch('/infrastructure/hosts' + getDomainParams()).then(r => r.json()),
            fetch('/infrastructure/users' + getDomainParams()).then(r => r.json()),
            fetch('/infrastructure/shares' + getDomainParams()).then(r => r.json()),
            fetch('/infrastructure/access' + getDomainParams()).then(r => r.json())
        ]);

        // Auto-populate if tables are empty and this is the first load
        if (!skipAutoPopulate && hosts.length === 0 && users.length === 0 && shares.length === 0) {
            if (container) container.innerHTML = '<div class="d-flex justify-content-center align-items-center h-100"><div class="spinner-border text-primary me-2"></div><span>Building infrastructure map from scan data...</span></div>';
            await fetch('/infrastructure/populate', { method: 'POST' });
            return loadInfrastructureData(true);
        }

        infrastructureGraphData = { hosts, users, shares, access };
        updateInfrastructureStats(hosts, users, shares, access);
        renderInfrastructureFilters();
        renderInfrastructureGraph();
        setupInfrastructureFilters();
    } catch (error) {
        console.error('Error loading infrastructure data:', error);
        showToast('Error loading infrastructure data.', 'error');
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

    // No data at all — show empty state
    const totalItems = infrastructureGraphData.hosts.length + infrastructureGraphData.users.length + infrastructureGraphData.shares.length;
    if (totalItems === 0) {
        container.innerHTML = `<div class="d-flex flex-column justify-content-center align-items-center h-100 text-muted">
            <i class="bi bi-diagram-3" style="font-size:3rem;opacity:0.3;"></i>
            <p class="mt-3">No infrastructure data found.</p>
            <small>Run a scan first, then click <strong>Update Data</strong> to import.</small>
        </div>`;
        return;
    }

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

    let existing = document.getElementById('nodeDetailPanel');
    if (existing) existing.remove();

    const nodeId = (node.id || '').toString();
    const parts = nodeId.split('_');
    const nodeType = parts[0]; // 'host', 'user', 'share', 'domain'

    const panel = document.createElement('div');
    panel.id = 'nodeDetailPanel';
    panel.style.cssText = 'position:fixed;top:80px;right:20px;z-index:9999;min-width:320px;max-width:460px;max-height:80vh;overflow-y:auto;';
    panel.innerHTML = `
        <div class="card shadow">
            <div class="card-header d-flex justify-content-between align-items-center" style="background:var(--secondary-color);color:white;">
                <strong>${nodeType ? nodeType.charAt(0).toUpperCase() + nodeType.slice(1) : 'Node'}: ${node.label || '-'}</strong>
                <button type="button" class="btn-close btn-close-white btn-sm" onclick="document.getElementById('nodeDetailPanel').remove()"></button>
            </div>
            <div class="card-body p-2">
                ${node.title ? `<p class="text-muted mb-2" style="font-size:0.82em;white-space:pre-line;">${node.title}</p>` : ''}
                <div id="nodeDetailContent">
                    <div class="text-center py-2"><div class="spinner-border spinner-border-sm" role="status"></div> Loading...</div>
                </div>
            </div>
        </div>
    `;
    document.body.appendChild(panel);
    loadNodeDetailData(nodeType, node.label, panel);
}

async function loadNodeDetailData(nodeType, label, panel) {
    const content = panel.querySelector('#nodeDetailContent');
    const domain = encodeURIComponent(selectedDomain || '');

    try {
        if (nodeType === 'host' || nodeType === 'share') {
            const resp = await fetch(`/infrastructure/nodes/files?type=${nodeType}&name=${encodeURIComponent(label)}&domain=${domain}`);
            const files = await resp.json();

            if (!files || files.length === 0) {
                content.innerHTML = '<p class="text-muted text-center mb-0">No files found.</p>';
                return;
            }
            content.innerHTML = `
                <p class="mb-1"><strong>Files found: ${files.length}</strong></p>
                <div style="max-height:340px;overflow-y:auto;">
                    <table class="table table-sm table-striped mb-0">
                        <tbody>${files.map(f => `
                            <tr>
                                <td style="font-size:0.78em;word-break:break-all;">${f.path}</td>
                                <td style="white-space:nowrap;">${f.classification_name ?
                                    `<span class="badge" style="background:${f.classification_color};font-size:0.7em;">${f.classification_name}</span>`
                                    : ''}</td>
                            </tr>`).join('')}
                        </tbody>
                    </table>
                </div>
            `;
        } else if (nodeType === 'user') {
            const resp = await fetch(`/infrastructure/nodes/user-access?username=${encodeURIComponent(label)}&domain=${domain}`);
            const accesses = await resp.json();

            if (!accesses || accesses.length === 0) {
                content.innerHTML = '<p class="text-muted text-center mb-0">No access records found.</p>';
                return;
            }
            content.innerHTML = `
                <p class="mb-1"><strong>Access records: ${accesses.length}</strong></p>
                <div style="max-height:340px;overflow-y:auto;">
                    <table class="table table-sm table-striped mb-0">
                        <thead><tr><th style="font-size:0.8em;">Target</th><th style="font-size:0.8em;">Type</th><th style="font-size:0.8em;">Access</th></tr></thead>
                        <tbody>${accesses.map(a => {
                            const bg = a.access_type === 'admin' ? '#dc3545' : a.access_type === 'write' ? '#fd7e14' : '#17a2b8';
                            return `<tr>
                                <td style="font-size:0.8em;">${a.target_name}</td>
                                <td style="font-size:0.8em;">${a.target_type}</td>
                                <td><span class="badge" style="background:${bg};font-size:0.7em;">${a.access_type}</span></td>
                            </tr>`;
                        }).join('')}
                        </tbody>
                    </table>
                </div>
            `;
        } else {
            content.innerHTML = '';
        }
    } catch (e) {
        content.innerHTML = '<p class="text-danger mb-0">Error loading details.</p>';
    }
}

async function populateInfrastructure() {
    try {
        const response = await fetch('/infrastructure/populate', { method: 'POST' });
        if (response.ok) {
            showToast('Infrastructure data updated successfully!');
            loadInfrastructureData();
        } else {
            const error = await response.json();
            showToast('Error updating data: ' + error.error, 'error');
        }
    } catch (error) {
        console.error('Error updating infrastructure:', error);
        showToast('Error updating infrastructure data.', 'error');
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
    const filters = ['showHosts', 'showUsers', 'showShares', 'showRead', 'showWrite', 'showAdmin'];
    filters.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.onchange = () => renderInfrastructureGraph();
    });
}

// ——— Report page ———

async function loadReportData() {
    const domainParams = getDomainParams();
    const content = document.getElementById('reportContent');
    if (!content) return;

    try {
        const resp = await fetch(`/report/data${domainParams}`);
        const data = await resp.json();

        const classStats = data.classification_stats || [];
        const criticalFiles = data.critical_files || [];
        const topHosts = data.top_hosts || [];
        const infra = data.infra_summary || {};
        const total = classStats.reduce((s, c) => s + (c.count || 0), 0);

        content.innerHTML = `
            <div class="row mb-4">
                <div class="col-md-6">
                    <div class="card h-100">
                        <div class="card-header"><h5 class="mb-0">Classification Summary</h5></div>
                        <div class="card-body">
                            <table class="table table-sm mb-0">
                                <thead><tr><th>Classification</th><th>Files</th><th>%</th></tr></thead>
                                <tbody>
                                    ${classStats.map(c => `
                                        <tr>
                                            <td><span class="badge" style="background:${c.color}">${c.name}</span></td>
                                            <td>${c.count}</td>
                                            <td>${total ? ((c.count / total) * 100).toFixed(1) : 0}%</td>
                                        </tr>`).join('')}
                                    <tr class="fw-bold border-top"><td>Total</td><td>${total}</td><td>100%</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="card h-100">
                        <div class="card-header"><h5 class="mb-0">Infrastructure Summary</h5></div>
                        <div class="card-body">
                            <table class="table table-sm mb-0">
                                <tbody>
                                    <tr><td><strong>Hosts</strong></td><td>${infra.hosts || 0}</td></tr>
                                    <tr><td><strong>Users</strong></td><td>${infra.users || 0} <span class="text-muted">(${infra.admin_users || 0} admins)</span></td></tr>
                                    <tr><td><strong>Shares</strong></td><td>${infra.shares || 0}</td></tr>
                                    <tr><td><strong>Total Files</strong></td><td>${data.total_files || 0}</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>

            ${criticalFiles.length > 0 ? `
            <div class="card mb-4">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <h5 class="mb-0">Critical Findings</h5>
                    <span class="badge bg-danger">${criticalFiles.length}</span>
                </div>
                <div class="card-body p-0">
                    <div class="table-responsive" style="max-height:400px;overflow-y:auto;">
                        <table class="table table-sm table-striped mb-0">
                            <thead class="sticky-top"><tr><th>Path</th><th>Host</th><th>Share</th><th>Size</th><th>Classification</th></tr></thead>
                            <tbody>
                                ${criticalFiles.map(f => `
                                    <tr>
                                        <td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:0.85em;" title="${f.path}">${f.path}</td>
                                        <td style="font-size:0.85em;">${f.host}</td>
                                        <td style="font-size:0.85em;">${f.share}</td>
                                        <td style="font-size:0.85em;">${formatSize(f.size)}</td>
                                        <td><span class="badge" style="background:${f.color};font-size:0.8em;">${f.classification}</span></td>
                                    </tr>`).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>` : ''}

            ${topHosts.length > 0 ? `
            <div class="card mb-4">
                <div class="card-header"><h5 class="mb-0">Top Hosts by File Count</h5></div>
                <div class="card-body p-0">
                    <table class="table table-sm table-striped mb-0">
                        <thead><tr><th>Host</th><th>Files</th></tr></thead>
                        <tbody>${topHosts.map(h => `<tr><td>${h.host}</td><td>${h.count}</td></tr>`).join('')}</tbody>
                    </table>
                </div>
            </div>` : ''}
        `;

        window._reportData = data;
    } catch (e) {
        if (content) content.innerHTML = '<p class="text-danger">Error loading report data.</p>';
        showToast('Error loading report data.', 'error');
    }
}

function downloadReport() {
    const data = window._reportData;
    if (!data) {
        showToast('No report data. Navigate to the Report page first.', 'warning');
        return;
    }

    const classStats = data.classification_stats || [];
    const criticalFiles = data.critical_files || [];
    const topHosts = data.top_hosts || [];
    const infra = data.infra_summary || {};
    const total = classStats.reduce((s, c) => s + (c.count || 0), 0);
    const domain = selectedDomain || 'All Domains';
    const date = new Date().toLocaleString();

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NullFang Report — ${date}</title>
<style>
body{font-family:Arial,sans-serif;margin:40px;color:#333;max-width:1100px;}
h1{color:#2c3e50;border-bottom:3px solid #dc3545;padding-bottom:8px;}
h2{color:#34495e;border-bottom:1px solid #eee;padding-bottom:6px;margin-top:30px;}
table{border-collapse:collapse;width:100%;margin-bottom:20px;}
th{background:#34495e;color:#fff;padding:8px 10px;text-align:left;}
td{padding:6px 10px;border-bottom:1px solid #eee;}
tr:nth-child(even){background:#f9f9f9;}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;color:#fff;font-size:.85em;}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:24px;}
.card{border:1px solid #ddd;border-radius:8px;padding:16px;}
.card h3{margin-top:0;color:#34495e;}
footer{margin-top:40px;color:#aaa;font-size:.8em;}
</style>
</head>
<body>
<h1>NullFang Engagement Report</h1>
<p><strong>Scope:</strong> ${domain} &nbsp;&nbsp; <strong>Generated:</strong> ${date}</p>
<div class="grid">
<div class="card">
<h3>Classification Summary</h3>
<table>
<tr><th>Classification</th><th>Files</th><th>%</th></tr>
${classStats.map(c => `<tr><td><span class="badge" style="background:${c.color}">${c.name}</span></td><td>${c.count}</td><td>${total ? ((c.count / total) * 100).toFixed(1) : 0}%</td></tr>`).join('')}
<tr style="font-weight:bold"><td>Total</td><td>${total}</td><td>100%</td></tr>
</table>
</div>
<div class="card">
<h3>Infrastructure</h3>
<table>
<tr><th>Category</th><th>Count</th></tr>
<tr><td>Hosts</td><td>${infra.hosts || 0}</td></tr>
<tr><td>Users</td><td>${infra.users || 0}</td></tr>
<tr><td>Admin Users</td><td>${infra.admin_users || 0}</td></tr>
<tr><td>Shares</td><td>${infra.shares || 0}</td></tr>
<tr><td>Total Files</td><td>${data.total_files || 0}</td></tr>
</table>
</div>
</div>
${criticalFiles.length > 0 ? `
<h2>Critical Findings (${criticalFiles.length})</h2>
<table>
<tr><th>Path</th><th>Host</th><th>Share</th><th>Size</th><th>Classification</th></tr>
${criticalFiles.map(f => `<tr><td>${f.path}</td><td>${f.host}</td><td>${f.share}</td><td>${formatSize(f.size)}</td><td><span class="badge" style="background:${f.color}">${f.classification}</span></td></tr>`).join('')}
</table>` : ''}
${topHosts.length > 0 ? `
<h2>Top Hosts by File Count</h2>
<table>
<tr><th>Host</th><th>Files Found</th></tr>
${topHosts.map(h => `<tr><td>${h.host}</td><td>${h.count}</td></tr>`).join('')}
</table>` : ''}
<footer>Generated by NullFang Web UI — For authorized security assessments only.</footer>
</body>
</html>`;

    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `nullfang_report_${new Date().toISOString().split('T')[0]}.html`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast('Report downloaded.');
}