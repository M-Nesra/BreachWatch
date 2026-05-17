let severityChart = null;
let currentDays = 30;
let allVulns = [];
let currentSort = 'score-desc';

function getNVDMetric(metricList) {
  if (!metricList || metricList.length === 0) return null;
  var nvd = null;
  var cna = null;
  metricList.forEach(function (m) {
    if (m.source === 'nvd@nist.gov') {
      nvd = m;
    } else {
      cna = m;
    }
  });
  if (nvd) return nvd;
  return cna;
}

function getSeverity(vuln) {
  const metrics = vuln.cve.metrics;
  var m = getNVDMetric(metrics.cvssMetricV31) || getNVDMetric(metrics.cvssMetricV30);
  if (m) return m.cvssData.baseSeverity;
  return 'UNKNOWN';
}

function getScore(vuln) {
  const metrics = vuln.cve.metrics;
  var m = getNVDMetric(metrics.cvssMetricV31) || getNVDMetric(metrics.cvssMetricV30);
  if (m) return m.cvssData.baseScore;
  return 0;
}

function getDescription(vuln) {
  const descs = vuln.cve.descriptions;
  const en = descs.find(function (d) { return d.lang === 'en'; });
  if (en) return en.value;
  return 'No description available.';
}

function getAffected(vuln) {
  try {
    const configs = vuln.cve.configurations;
    if (!configs || configs.length === 0) return '';
    const vendors = [];
    configs.forEach(function (config) {
      if (config.nodes) {
        config.nodes.forEach(function (node) {
          if (node.cpeMatch) {
            node.cpeMatch.forEach(function (match) {
              const parts = match.criteria.split(':');
              if (parts[3] && vendors.indexOf(parts[3]) === -1) {
                vendors.push(parts[3]);
              }
            });
          }
        });
      }
    });
    return vendors.slice(0, 3).join(', ');
  } catch (e) {
    return '';
  }
}

function formatDate(dateStr) {
  if (!dateStr) return '';
  return new Date(dateStr).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
}

function showToast(message) {
  const toast = document.getElementById('toast');
  toast.innerHTML = message;
  toast.style.display = 'block';
  setTimeout(function () {
    toast.style.display = 'none';
  }, 3000);
}

function saveCVE(cveId, severity, description, affected, btn) {
  fetch('/api/saved', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      cve_id: cveId,
      severity: severity,
      description: description.substring(0, 300),
      affected_software: affected
    })
  })
    .then(function (result) { return result.json(); })
    .then(function (resultJson) {
      if (resultJson.error && resultJson.error === 'CVE already saved') {
        showToast(cveId + ' is already in your watchlist');
        btn.innerHTML = 'Saved';
        btn.classList.add('saved');
      } else if (resultJson.error) {
        showToast('Could not save: ' + resultJson.error);
        btn.innerHTML = '+ Save';
        btn.disabled = false;
      } else {
        showToast(cveId + ' added to watchlist');
        btn.innerHTML = 'Saved';
        btn.classList.add('saved');
      }
    });
}

function getExtraDetail(vuln) {
  const details = {};
  try {
    const metrics = vuln.cve.metrics;
    var m = getNVDMetric(metrics.cvssMetricV31) || getNVDMetric(metrics.cvssMetricV30);
    if (m) {
      details.vector = m.cvssData.vectorString || '';
      details.exploitability = m.exploitabilityScore || '';
      details.impact = m.impactScore || '';
      details.attackVector = m.cvssData.attackVector || '';
      details.complexity = m.cvssData.attackComplexity || '';
      details.privileges = m.cvssData.privilegesRequired || '';
      details.userInteraction = m.cvssData.userInteraction || '';
    }
  } catch (e) {}
  try { details.modified = formatDate(vuln.cve.lastModified); } catch (e) {}
  try {
    const refs = vuln.cve.references || [];
    details.refs = refs.slice(0, 3);
  } catch (e) { details.refs = []; }
  return details;
}

function buildCard(vuln) {
  const id = vuln.cve.id;
  const severity = getSeverity(vuln);
  const score = getScore(vuln);
  const desc = getDescription(vuln);
  const published = formatDate(vuln.cve.published);
  const affected = getAffected(vuln);
  const sourceUrl = 'https://nvd.nist.gov/vuln/detail/' + id;
  const extra = getExtraDetail(vuln);

  const card = document.createElement('div');
  card.setAttribute('class', 'cve-card');

  const idEl = document.createElement('div');
  idEl.setAttribute('class', 'cve-id');
  idEl.innerHTML = id;

  const badge = document.createElement('span');
  badge.setAttribute('class', 'badge badge-' + severity);
  badge.innerHTML = severity.charAt(0).toUpperCase() + severity.slice(1).toLowerCase();

  const scoreEl = document.createElement('div');
  scoreEl.setAttribute('class', 'cve-score');
  if (score) {
    scoreEl.innerHTML = score + ' <small>/ 10</small>';
  }

  const descEl = document.createElement('p');
  descEl.setAttribute('class', 'cve-desc');
  descEl.innerHTML = desc;

  const metaEl = document.createElement('div');
  metaEl.setAttribute('class', 'cve-meta');
  if (affected) {
    metaEl.innerHTML = 'Published: ' + published + ' | Affected: ' + affected;
  } else {
    metaEl.innerHTML = 'Published: ' + published;
  }

  const expandEl = document.createElement('div');
  expandEl.setAttribute('class', 'cve-expand');
  expandEl.style.display = 'none';

  let expandHTML = '<div class="expand-divider"></div>';
  expandHTML += '<p class="expand-full-desc">' + desc + '</p>';

  if (extra.modified) {
    expandHTML += '<div class="expand-row"><span class="expand-label">Last Modified</span><span>' + extra.modified + '</span></div>';
  }
  if (extra.attackVector) {
    expandHTML += '<div class="expand-row"><span class="expand-label">Attack Vector</span><span>' + extra.attackVector + '</span></div>';
  }
  if (extra.complexity) {
    expandHTML += '<div class="expand-row"><span class="expand-label">Complexity</span><span>' + extra.complexity + '</span></div>';
  }
  if (extra.privileges) {
    expandHTML += '<div class="expand-row"><span class="expand-label">Privileges Required</span><span>' + extra.privileges + '</span></div>';
  }
  if (extra.userInteraction) {
    expandHTML += '<div class="expand-row"><span class="expand-label">User Interaction</span><span>' + extra.userInteraction + '</span></div>';
  }
  if (extra.exploitability) {
    expandHTML += '<div class="expand-row"><span class="expand-label">Exploitability Score</span><span>' + extra.exploitability + '</span></div>';
  }
  if (extra.impact) {
    expandHTML += '<div class="expand-row"><span class="expand-label">Impact Score</span><span>' + extra.impact + '</span></div>';
  }
  if (extra.vector) {
    expandHTML += '<div class="expand-row"><span class="expand-label">CVSS Vector</span><span class="expand-vector">' + extra.vector + '</span></div>';
  }
  if (extra.refs && extra.refs.length > 0) {
    expandHTML += '<div class="expand-label expand-refs-label">References</div>';
    extra.refs.forEach(function (ref) {
      expandHTML += '<div><a href="' + ref.url + '" target="_blank" class="expand-ref">' + ref.url + '</a></div>';
    });
  }

  expandEl.innerHTML = expandHTML;

  const toggleHint = document.createElement('div');
  toggleHint.setAttribute('class', 'expand-hint');
  toggleHint.innerHTML = 'Click to expand';

  const actions = document.createElement('div');
  actions.setAttribute('class', 'card-actions');

  const saveBtn = document.createElement('button');
  saveBtn.setAttribute('class', 'btn-save');
  saveBtn.innerHTML = '+ Save';
  saveBtn.onclick = function (e) {
    e.stopPropagation();
    saveBtn.innerHTML = '...';
    saveBtn.disabled = true;
    saveCVE(id, severity, desc, affected, saveBtn);
  };

  const sourceBtn = document.createElement('a');
  sourceBtn.setAttribute('class', 'btn-source');
  sourceBtn.setAttribute('href', sourceUrl);
  sourceBtn.setAttribute('target', '_blank');
  sourceBtn.innerHTML = 'Source';
  sourceBtn.onclick = function (e) {
    e.stopPropagation();
  };

  actions.appendChild(saveBtn);
  actions.appendChild(sourceBtn);

  card.appendChild(idEl);
  card.appendChild(badge);
  card.appendChild(scoreEl);
  card.appendChild(descEl);
  card.appendChild(metaEl);
  card.appendChild(toggleHint);
  card.appendChild(expandEl);
  card.appendChild(actions);

  card.onclick = function () {
    const isOpen = expandEl.style.display === 'block';
    if (isOpen) {
      expandEl.style.display = 'none';
      descEl.setAttribute('class', 'cve-desc');
      toggleHint.innerHTML = 'Click to expand';
      card.classList.remove('cve-card-open');
    } else {
      expandEl.style.display = 'block';
      descEl.setAttribute('class', 'cve-desc cve-desc-open');
      toggleHint.innerHTML = 'Click to collapse';
      card.classList.add('cve-card-open');
    }
  };

  return card;
}

function sortVulns(vulns, sortType) {
  const sorted = vulns.slice();
  if (sortType === 'date-desc') {
    sorted.sort(function (a, b) {
      return new Date(b.cve.published) - new Date(a.cve.published);
    });
  } else if (sortType === 'date-asc') {
    sorted.sort(function (a, b) {
      return new Date(a.cve.published) - new Date(b.cve.published);
    });
  } else if (sortType === 'score-desc') {
    sorted.sort(function (a, b) {
      return getScore(b) - getScore(a);
    });
  } else if (sortType === 'score-asc') {
    sorted.sort(function (a, b) {
      return getScore(a) - getScore(b);
    });
  }
  return sorted;
}

function renderCards(vulns) {
  const container = document.getElementById('cardsContainer');
  container.innerHTML = '';

  if (vulns.length === 0) {
    container.innerHTML = '<p class="loading-msg">No CVEs found in the last ' + currentDays + ' days.</p>';
    return;
  }

  const grid = document.createElement('div');
  grid.setAttribute('class', 'cards-grid');

  vulns.forEach(function (vuln) {
    const card = buildCard(vuln);
    grid.appendChild(card);
  });

  container.appendChild(grid);
}

function renderChart(vulns) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  vulns.forEach(function (vuln) {
    const s = getSeverity(vuln);
    if (counts[s] !== undefined) {
      counts[s]++;
    }
  });

  const chartSection = document.getElementById('chartSection');
  chartSection.classList.remove('hidden');

  if (severityChart) {
    severityChart.destroy();
  }

  severityChart = new Chart(document.getElementById('severityChart'), {
    type: 'bar',
    data: {
      labels: ['Critical', 'High', 'Medium', 'Low'],
      datasets: [{
        label: 'CVE Count',
        data: [counts.CRITICAL, counts.HIGH, counts.MEDIUM, counts.LOW],
        backgroundColor: [
          'rgba(214, 48, 49, 0.7)',
          'rgba(225, 112, 85, 0.7)',
          'rgba(243, 156, 18, 0.7)',
          'rgba(0, 184, 148, 0.7)'
        ],
        borderColor: [
          'rgba(214, 48, 49, 1)',
          'rgba(225, 112, 85, 1)',
          'rgba(243, 156, 18, 1)',
          'rgba(0, 184, 148, 1)'
        ],
        borderWidth: 1,
        borderRadius: 6
      }]
    },
    options: {
      responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: '#f0eef9' }, ticks: { color: '#4a4a6a' } },
        y: { beginAtZero: true, grid: { color: '#f0eef9' }, ticks: { color: '#4a4a6a', stepSize: 1 } }
      }
    }
  });
}

function changeSort(sortType) {
  currentSort = sortType;
  document.querySelectorAll('.sort-btn').forEach(function (b) {
    b.classList.remove('active');
  });
  document.getElementById('sort-' + sortType).classList.add('active');
  const sorted = sortVulns(allVulns, currentSort);
  renderCards(sorted);
}

async function loadCriticalCVEs() {
  document.getElementById('cardsContainer').innerHTML = '<p class="loading-msg">Loading vulnerabilities...</p>';
  document.getElementById('critCount').innerHTML = '';
  document.getElementById('chartSection').classList.add('hidden');

  await fetch('/api/critical?days=' + currentDays)
    .then(function (result) { return result.json(); })
    .then(function (resultJson) {
      allVulns = resultJson.vulnerabilities || [];

      document.getElementById('critCount').innerHTML = allVulns.length + ' results';

      const sorted = sortVulns(allVulns, currentSort);
      renderCards(sorted);
      renderChart(allVulns);
    })
    .catch(function (err) {
      document.getElementById('cardsContainer').innerHTML =
        '<p class="error-msg">Failed to load vulnerability data. Please try again shortly.</p>';
    });
}

function changeDays(days, btn) {
  currentDays = days;
  document.querySelectorAll('.days-btn').forEach(function (b) {
    b.classList.remove('active');
  });
  btn.classList.add('active');
  loadCriticalCVEs();
}

function goToSearch() {
  const q = document.getElementById('homeSearch').value.trim();
  if (!q) return;
  window.location.href = 'search.html?q=' + encodeURIComponent(q);
}

window.onload = function () {
  loadCriticalCVEs();

  document.getElementById('homeSearch').addEventListener('keydown', function (e) {
    if (e.key === 'Enter') goToSearch();
  });
};
