// DFD Threat Model Generator - Frontend Application

const API_BASE = '/api';
let dfdData = {
  id: generateId(),
  name: '',
  description: '',
  elements: [],
  dataflows: [],
  trustBoundaries: []
};

let threatModel = null;
let threatReport = null;

// Generate unique ID
function generateId() {
  return 'id_' + Math.random().toString(36).substr(2, 9);
}

// Add element to DFD
function addElement() {
  const name = document.getElementById('elementName').value.trim();
  const type = document.getElementById('elementType').value;

  if (!name || !type) {
    alert('Please enter element name and select type');
    return;
  }

  const element = {
    id: generateId(),
    name,
    type,
    description: `${name} (${type})`,
    trustLevel: type === 'external_entity' ? 'untrusted' : 'trusted'
  };

  dfdData.elements.push(element);
  updateElementsList();
  updateDropdowns();
  document.getElementById('elementName').value = '';
  document.getElementById('elementType').value = '';
}

// Remove element
function removeElement(id) {
  dfdData.elements = dfdData.elements.filter(e => e.id !== id);
  updateElementsList();
  updateDropdowns();
}

// Update elements display
function updateElementsList() {
  const list = document.getElementById('elementsList');
  if (dfdData.elements.length === 0) {
    list.innerHTML = '<p style="color: #999; font-size: 0.9em;">No elements added yet</p>';
    return;
  }

  list.innerHTML = dfdData.elements.map(el => `
    <div style="background: #f9f9f9; padding: 10px; margin-bottom: 8px; border-radius: 4px; display: flex; justify-content: space-between; align-items: center;">
      <div>
        <strong>${el.name}</strong>
        <span style="color: #666; font-size: 0.85em; margin-left: 10px;">${el.type}</span>
      </div>
      <button class="btn-secondary btn-small" onclick="removeElement('${el.id}')">Remove</button>
    </div>
  `).join('');
}

// Update dropdown options
function updateDropdowns() {
  const fromSelect = document.getElementById('dataflowFrom');
  const toSelect = document.getElementById('dataflowTo');
  const options = dfdData.elements.map(el => `<option value="${el.id}">${el.name}</option>`).join('');
  
  fromSelect.innerHTML = '<option value="">-- From --</option>' + options;
  toSelect.innerHTML = '<option value="">-- To --</option>' + options;
}

// Add dataflow
function addDataflow() {
  const name = document.getElementById('dataflowName').value.trim();
  const from = document.getElementById('dataflowFrom').value;
  const to = document.getElementById('dataflowTo').value;
  const protocol = document.getElementById('dataflowProtocol').value.trim();
  const hasSensitiveData = document.getElementById('hasSensitiveData').checked;

  if (!name || !from || !to) {
    alert('Please fill in all required fields');
    return;
  }

  if (from === to) {
    alert('Source and destination cannot be the same');
    return;
  }

  const dataflow = {
    id: generateId(),
    name,
    from,
    to,
    protocol: protocol || 'HTTPS',
    hasSensitiveData,
    isEncrypted: protocol?.toUpperCase().includes('HTTPS') || protocol?.toUpperCase().includes('TLS'),
    isCrossNetwork: false,
    type: 'dataflow'
  };

  dfdData.dataflows.push(dataflow);
  updateDataflowsList();
  document.getElementById('dataflowName').value = '';
  document.getElementById('dataflowFrom').value = '';
  document.getElementById('dataflowTo').value = '';
  document.getElementById('dataflowProtocol').value = '';
  document.getElementById('hasSensitiveData').checked = false;
}

// Remove dataflow
function removeDataflow(id) {
  dfdData.dataflows = dfdData.dataflows.filter(df => df.id !== id);
  updateDataflowsList();
}

// Update dataflows display
function updateDataflowsList() {
  const list = document.getElementById('dataflowsList');
  if (dfdData.dataflows.length === 0) {
    list.innerHTML = '<p style="color: #999; font-size: 0.9em;">No dataflows added yet</p>';
    return;
  }

  list.innerHTML = dfdData.dataflows.map(df => {
    const fromName = dfdData.elements.find(e => e.id === df.from)?.name || 'Unknown';
    const toName = dfdData.elements.find(e => e.id === df.to)?.name || 'Unknown';
    return `
      <div style="background: #f9f9f9; padding: 10px; margin-bottom: 8px; border-radius: 4px;">
        <div style="display: flex; justify-content: space-between; align-items: start;">
          <div style="flex: 1;">
            <strong>${df.name}</strong>
            <div style="color: #666; font-size: 0.85em; margin-top: 5px;">
              ${fromName} → ${toName} (${df.protocol})
            </div>
            ${df.hasSensitiveData ? '<span style="color: #cc0000; font-size: 0.85em;">🔒 Sensitive Data</span>' : ''}
          </div>
          <button class="btn-secondary btn-small" onclick="removeDataflow('${df.id}')">Remove</button>
        </div>
      </div>
    `;
  }).join('');
}

// Clear form
function clearForm() {
  if (confirm('Clear all data? This cannot be undone.')) {
    dfdData = {
      id: generateId(),
      name: '',
      description: '',
      elements: [],
      dataflows: [],
      trustBoundaries: []
    };
    threatModel = null;
    threatReport = null;
    document.getElementById('dfdName').value = '';
    document.getElementById('dfdDescription').value = '';
    updateElementsList();
    updateDataflowsList();
    updateDropdowns();
    document.getElementById('resultsContent').innerHTML = '<p style="margin-top: 40px; color: #999;">Results will appear here after generation</p>';
    document.getElementById('threatsSection').style.display = 'none';
  }
}

// Generate threat model
async function generateThreatModel() {
  const name = document.getElementById('dfdName').value.trim();
  const description = document.getElementById('dfdDescription').value.trim();

  if (!name) {
    alert('Please enter project name');
    return;
  }

  if (dfdData.elements.length === 0) {
    alert('Please add at least one element');
    return;
  }

  if (dfdData.dataflows.length === 0) {
    alert('Please add at least one dataflow');
    return;
  }

  dfdData.name = name;
  dfdData.description = description;

  // Show loading
  const resultsDiv = document.getElementById('resultsContent');
  resultsDiv.innerHTML = '<div class="loading"><div class="spinner"></div><p>Analyzing DFD and generating threats...</p></div>';

  try {
    const response = await fetch(`${API_BASE}/threats/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ dfd: dfdData })
    });

    const result = await response.json();

    if (!result.success) {
      resultsDiv.innerHTML = `<div class="error">${result.errors.join('<br>')}</div>`;
      return;
    }

    threatModel = result.threatModel;

    // Generate report
    const reportResponse = await fetch(`${API_BASE}/reports/threat-analysis`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ dfd: dfdData })
    });

    const reportResult = await reportResponse.json();
    if (reportResult.success) {
      threatReport = reportResult.report;
    }

    // Display results
    displayResults(result.summary);
    displayThreats();
    displaySeverityBreakdown();
    displaySTRIDEBreakdown();
    displayReport();
    
    document.getElementById('threatsSection').style.display = 'block';
  } catch (error) {
    resultsDiv.innerHTML = `<div class="error">Error: ${error.message}</div>`;
  }
}

// Display summary results
function displayResults(summary) {
  const html = `
    <div class="summary-stats">
      <div class="stat-box">
        <div class="stat-number">${summary.totalElements}</div>
        <div class="stat-label">Elements</div>
      </div>
      <div class="stat-box">
        <div class="stat-number">${summary.totalDataflows}</div>
        <div class="stat-label">Data Flows</div>
      </div>
      <div class="stat-box critical">
        <div class="stat-number">${summary.riskLevels.critical}</div>
        <div class="stat-label">Critical</div>
      </div>
      <div class="stat-box high">
        <div class="stat-number">${summary.riskLevels.high}</div>
        <div class="stat-label">High</div>
      </div>
    </div>
    <p><strong>Total Threats Identified:</strong> ${summary.threatsIdentified}</p>
  `;
  document.getElementById('resultsContent').innerHTML = html;
}

// Display all threats
function displayThreats() {
  if (!threatModel || !threatModel.threats) return;

  const html = threatModel.threats.map(threat => `
    <div class="threat-item ${threat.severity.toLowerCase()}">
      <div class="threat-title">
        ${threat.title}
        <span class="severity-badge severity-${threat.severity.toLowerCase()}">${threat.severity}</span>
      </div>
      <div class="threat-description">${threat.description}</div>
      <div><strong>Category:</strong> ${threat.category}</div>
      <div><strong>Impact:</strong> ${threat.impact}</div>
      ${threat.elementName ? `<div><strong>Element:</strong> ${threat.elementName}</div>` : ''}
      ${threat.dataflowName ? `<div><strong>Data Flow:</strong> ${threat.dataflowName}</div>` : ''}
      <div class="stride-tags">
        ${threat.stride.map(s => `<span class="stride-tag">${s}</span>`).join('')}
      </div>
      ${threat.mitigations && threat.mitigations.length > 0 ? `
        <div class="mitigations">
          <h4>Recommended Mitigations:</h4>
          <ul>
            ${threat.mitigations.map(m => `<li>${m}</li>`).join('')}
          </ul>
        </div>
      ` : ''}
    </div>
  `).join('');

  document.getElementById('threatsList').innerHTML = html || '<p>No threats identified</p>';
}

// Display severity breakdown
function displaySeverityBreakdown() {
  if (!threatModel) return;

  const severities = ['Critical', 'High', 'Medium', 'Low'];
  let html = '';

  severities.forEach(sev => {
    const threats = threatModel.threats.filter(t => t.severity === sev);
    if (threats.length > 0) {
      html += `<h3 style="color: #333; margin-top: 20px; margin-bottom: 10px;">${sev} Severity (${threats.length})</h3>`;
      html += threats.map(threat => `
        <div class="threat-item ${sev.toLowerCase()}">
          <div class="threat-title">${threat.title}</div>
          <div class="threat-description">${threat.description}</div>
        </div>
      `).join('');
    }
  });

  document.getElementById('severityBreakdown').innerHTML = html || '<p>No threats</p>';
}

// Display STRIDE breakdown
function displaySTRIDEBreakdown() {
  if (!threatReport || !threatReport.stride_breakdown) return;

  let html = '';
  for (const [category, threats] of Object.entries(threatReport.stride_breakdown)) {
    html += `<h3 style="color: #333; margin-top: 20px; margin-bottom: 10px;">${category} (${threats.length})</h3>`;
    html += threats.map(threat => `
      <div class="threat-item">
        <div class="threat-title">${threat.title}</div>
        <div class="threat-description">${threat.description}</div>
      </div>
    `).join('');
  }

  document.getElementById('strideBreakdown').innerHTML = html || '<p>No STRIDE breakdown available</p>';
}

// Display report
function displayReport() {
  if (!threatReport) return;

  const summary = threatReport.executive_summary;
  let html = `
    <h3>Executive Summary</h3>
    <p><strong>Overall Risk Level:</strong> ${summary.overall_risk}</p>
    <ul>
      <li>Total Threats: ${summary.total_threats}</li>
      <li>Critical: ${summary.critical_threats}</li>
      <li>High: ${summary.high_threats}</li>
      <li>Medium: ${summary.medium_threats}</li>
      <li>Low: ${summary.low_threats}</li>
    </ul>

    <h3 style="margin-top: 20px;">Recommendations</h3>
  `;

  if (threatReport.recommendations && threatReport.recommendations.length > 0) {
    html += '<ul>';
    threatReport.recommendations.forEach(rec => {
      html += `
        <li>
          <strong>[${rec.priority}]</strong> ${rec.action}
          <div style="color: #666; font-size: 0.9em; margin: 5px 0;">${rec.details}</div>
          <div style="color: #999; font-size: 0.85em;">Timeline: ${rec.timeline}</div>
        </li>
      `;
    });
    html += '</ul>';
  }

  document.getElementById('reportContent').innerHTML = html;
}

// Switch tab
function switchTab(e, tabName) {
  // Hide all tabs
  document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.tab-button').forEach(el => el.classList.remove('active'));

  // Show selected tab
  document.getElementById(tabName).classList.add('active');
  e.target.classList.add('active');
}

// Export JSON
function exportJSON() {
  if (!threatModel) {
    alert('No threat model to export');
    return;
  }

  const data = {
    dfd: dfdData,
    threatModel: threatModel,
    report: threatReport,
    exportedAt: new Date().toISOString()
  };

  downloadFile(JSON.stringify(data, null, 2), `${dfdData.name}_threat_model.json`, 'application/json');
}

// Export CSV
function exportCSV() {
  if (!threatModel || !threatModel.threats) {
    alert('No threats to export');
    return;
  }

  let csv = 'Title,Category,Severity,Impact,STRIDE,Element,Mitigations\n';
  threatModel.threats.forEach(threat => {
    const stride = threat.stride.join('|');
    const mitigations = threat.mitigations.join('|');
    const element = threat.elementName || threat.dataflowName || 'N/A';
    csv += `"${threat.title}","${threat.category}","${threat.severity}","${threat.impact}","${stride}","${element}","${mitigations}"\n`;
  });

  downloadFile(csv, `${dfdData.name}_threats.csv`, 'text/csv');
}

// Download file helper
function downloadFile(content, filename, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  window.URL.revokeObjectURL(url);
}

// Print report
function printReport() {
  window.print();
}
