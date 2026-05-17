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

function removeCVE(cveId, rowEl) {
  fetch('/api/saved/' + encodeURIComponent(cveId), { method: 'DELETE' })
    .then(function (result) { return result.json(); })
    .then(function (resultJson) {
      if (resultJson.error) {
        showToast('Could not remove: ' + resultJson.error);
        return;
      }
      rowEl.remove();
      showToast(cveId + ' removed from watchlist');

      const rows = document.querySelectorAll('#savedTable tr');
      document.getElementById('savedCount').innerHTML = (rows.length - 1) + ' saved';

      if (rows.length <= 1) {
        document.getElementById('savedTable').classList.add('hidden');
        document.getElementById('savedContainer').innerHTML =
          '<p class="loading-msg">Your watchlist is empty. <a href="search.html" class="search-link">Search for CVEs</a> to add some.</p>';
      }
    });
}

async function loadSaved() {
  await fetch('/api/saved')
    .then(function (result) { return result.json(); })
    .then(function (resultJson) {
      const items = resultJson.data || [];

      document.getElementById('savedCount').innerHTML = items.length + ' saved';
      document.getElementById('savedContainer').innerHTML = '';

      if (resultJson.message && items.length === 0) {
        document.getElementById('savedContainer').innerHTML =
          '<p class="error-msg">Supabase not configured. Add SUPABASE_URL and SUPABASE_ANON_KEY to your .env file.</p>';
        return;
      }

      if (items.length === 0) {
        document.getElementById('savedContainer').innerHTML =
          '<p class="loading-msg">Your watchlist is empty. <a href="search.html" class="search-link">Search for CVEs</a> to add some.</p>';
        return;
      }

      const table = document.getElementById('savedTable');
      table.classList.remove('hidden');

      items.forEach(function (item) {
        const row = document.createElement('tr');

        const idCell = document.createElement('td');
        idCell.innerHTML = '<strong>' + item.cve_id + '</strong>';

        const sevCell = document.createElement('td');
        sevCell.innerHTML = '<span class="badge badge-' + item.severity + '">' + item.severity.charAt(0).toUpperCase() + item.severity.slice(1).toLowerCase() + '</span>';

        const descCell = document.createElement('td');
        descCell.setAttribute('class', 'desc-cell');
        if (item.description) {
          descCell.innerHTML = item.description.substring(0, 120) + '...';
        } else {
          descCell.innerHTML = 'No description';
        }

        const affCell = document.createElement('td');
        if (item.affected_software) {
          affCell.innerHTML = item.affected_software;
        } else {
          affCell.innerHTML = 'N/A';
        }

        const dateCell = document.createElement('td');
        dateCell.innerHTML = formatDate(item.saved_at);

        const actionCell = document.createElement('td');
        const removeBtn = document.createElement('button');
        removeBtn.setAttribute('class', 'btn-remove');
        removeBtn.innerHTML = 'X Remove';
        removeBtn.onclick = function () {
          removeCVE(item.cve_id, row);
        };
        actionCell.appendChild(removeBtn);

        row.appendChild(idCell);
        row.appendChild(sevCell);
        row.appendChild(descCell);
        row.appendChild(affCell);
        row.appendChild(dateCell);
        row.appendChild(actionCell);

        table.appendChild(row);
      });
    })
    .catch(function (err) {
      document.getElementById('savedContainer').innerHTML =
        '<p class="error-msg">Failed to load watchlist. Please try again.</p>';
    });
}

window.onload = function () {
  loadSaved();
};
