(() => {
  const form = document.getElementById('scan-form');
  const flash = document.getElementById('scan-flash');
  const tableBody = document.getElementById('scans-table-body');
  const modal = document.getElementById('scan-results-modal');
  const modalClose = document.getElementById('close-results-modal');
  const resultsBody = document.getElementById('scan-results-body');
  const promoteSelectedBtn = document.getElementById('promote-selected-btn');
  const resultSummary = document.getElementById('result-summary');

  let activeScanId = null;

  function flashMsg(message, isError = false) {
    flash.textContent = message;
    flash.className = `mt-3 text-sm ${isError ? 'text-rose-500' : 'text-emerald-500'}`;
  }

  async function loadScans() {
    const res = await fetch('/api/scans?limit=100');
    if (!res.ok) return;
    const data = await res.json();

    tableBody.innerHTML = '';
    for (const scan of data.scans || []) {
      const tr = document.createElement('tr');
      tr.className = 'border-t border-slate-200 dark:border-slate-800';
      tr.innerHTML = `
        <td class="px-3 py-2">${scan.id}</td>
        <td class="px-3 py-2">${scan.target}</td>
        <td class="px-3 py-2">${scan.status}</td>
        <td class="px-3 py-2">${scan.findingsCount}</td>
        <td class="px-3 py-2">${scan.promotedFindingsCount ?? 0}</td>
        <td class="px-3 py-2">
          <button data-scan-id="${scan.id}" class="open-results rounded-lg border border-slate-300 px-2.5 py-1 text-xs hover:bg-slate-100 dark:border-slate-700 dark:hover:bg-slate-800">Results</button>
        </td>
      `;
      tableBody.appendChild(tr);
    }

    document.querySelectorAll('.open-results').forEach((btn) => {
      btn.addEventListener('click', () => openScanResults(Number(btn.dataset.scanId)));
    });
  }

  async function openScanResults(scanId) {
    activeScanId = scanId;
    const res = await fetch(`/api/scans/${scanId}/results`);
    if (!res.ok) return;
    const data = await res.json();

    resultSummary.textContent = `Scan #${scanId} · ${data.count} results · Only selected items will be promoted to findings`;
    resultsBody.innerHTML = '';

    for (const result of data.results || []) {
      const cve = (result.cveIds && result.cveIds.length) ? result.cveIds[0] : '-';
      const tr = document.createElement('tr');
      tr.className = 'border-t border-slate-200 dark:border-slate-800';
      tr.innerHTML = `
        <td class="px-3 py-2"><input type="checkbox" class="result-select" value="${result.resultId}" checked></td>
        <td class="px-3 py-2">${result.severity || 'info'}</td>
        <td class="px-3 py-2">${cve}</td>
        <td class="px-3 py-2">${result.cvssScore ?? '-'}</td>
        <td class="px-3 py-2">${result.templateName || result.templateId || '-'}</td>
        <td class="px-3 py-2">${result.host || '-'}</td>
        <td class="px-3 py-2 max-w-[320px] truncate" title="${result.description || ''}">${result.description || '-'}</td>
      `;
      resultsBody.appendChild(tr);
    }

    modal.classList.remove('hidden');
    modal.classList.add('flex');
  }

  async function promoteSelected() {
    if (!activeScanId) return;
    const selected = [...document.querySelectorAll('.result-select:checked')].map((el) => Number(el.value));

    const res = await fetch(`/api/scans/${activeScanId}/promote-findings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ selectedResultIds: selected }),
    });

    const data = await res.json();
    if (!res.ok) {
      flashMsg(data.error || 'Promotion failed', true);
      return;
    }

    flashMsg(`${data.promoted} results promoted to findings.`);
    modal.classList.add('hidden');
    modal.classList.remove('flex');
    await loadScans();
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();

    const payload = {
      target: form.target.value,
      template: form.template.value,
      severity: form.severity.value,
      tags: form.tags.value,
      advancedArgs: form.advancedArgs.value,
    };

    const res = await fetch('/api/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    const data = await res.json();
    if (!res.ok) {
      flashMsg(data.error || 'Scan could not be started', true);
      return;
    }

    flashMsg(`Scan #${data.scan.id} started.`);
    form.reset();
    await loadScans();
  });

  modalClose.addEventListener('click', () => {
    modal.classList.add('hidden');
    modal.classList.remove('flex');
  });
  promoteSelectedBtn.addEventListener('click', promoteSelected);

  loadScans();
  setInterval(loadScans, 5000);
})();
