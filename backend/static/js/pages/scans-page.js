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
  let refreshHandle = null;

  function escapeHtml(value) {
    return String(value ?? '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#039;');
  }

  function statusClass(status) {
    const normalized = String(status || '').toLowerCase();
    if (normalized === 'completed') return 'scan-status scan-status--completed';
    if (normalized === 'running') return 'scan-status scan-status--running';
    if (normalized === 'failed') return 'scan-status scan-status--failed';
    return 'scan-status scan-status--queued';
  }

  function computeProgress(scan) {
    const status = String(scan.status || '').toLowerCase();
    if (status === 'completed') return 100;
    if (status === 'failed') return 100;
    if (status === 'queued') return 10;
    if (status === 'running') return (scan.findingsCount || 0) > 0 ? 85 : 60;
    return 0;
  }

  function processStep(scan) {
    const status = String(scan.status || '').toLowerCase();
    if (status === 'queued') return 'Queued for execution';
    if (status === 'running') return 'Nuclei engine running';
    if (status === 'completed') return 'Completed and ready for review';
    if (status === 'failed') return 'Execution failed';
    return 'State unknown';
  }

  function timeAgo(isoString) {
    if (!isoString) return '-';
    const delta = Math.floor((Date.now() - new Date(isoString).getTime()) / 1000);
    if (delta < 60) return `${Math.max(delta, 1)}s ago`;
    if (delta < 3600) return `${Math.floor(delta / 60)}m ago`;
    if (delta < 86400) return `${Math.floor(delta / 3600)}h ago`;
    return `${Math.floor(delta / 86400)}d ago`;
  }

  function flashMsg(message, isError = false) {
    flash.textContent = message;
    flash.className = `mt-3 text-sm ${isError ? 'text-rose-500' : 'text-emerald-500'}`;
  }

  async function loadScans() {
    const res = await fetch('/api/scans?limit=100');
    if (!res.ok) return;
    const data = await res.json();
    const scans = data.scans || [];

    tableBody.innerHTML = '';
    for (const scan of scans) {
      const progress = computeProgress(scan);
      const status = escapeHtml(scan.status || 'queued');
      const target = escapeHtml(scan.target || '-');
      const updated = timeAgo(scan.updatedAt);
      const tr = document.createElement('tr');
      tr.className = 'border-t border-slate-200 dark:border-slate-800';
      tr.innerHTML = `
        <td class="px-3 py-2">${scan.id}</td>
        <td class="px-3 py-2 max-w-[220px] truncate" title="${target}">${target}</td>
        <td class="px-3 py-2"><span class="${statusClass(scan.status)}">${status}</span></td>
        <td class="px-3 py-2">
          <div class="scan-progress-wrap">
            <div class="scan-progress-track"><span class="scan-progress-fill ${String(scan.status).toLowerCase() === 'failed' ? 'scan-progress-fill--failed' : ''}" style="width:${progress}%"></span></div>
            <p class="scan-progress-label">${progress}%</p>
            <p class="scan-process-step">${processStep(scan)}</p>
          </div>
        </td>
        <td class="px-3 py-2">${scan.findingsCount}</td>
        <td class="px-3 py-2">${scan.promotedFindingsCount ?? 0}</td>
        <td class="px-3 py-2 text-xs text-slate-500 dark:text-slate-400">${updated}</td>
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
  refreshHandle = setInterval(loadScans, 3000);

  window.addEventListener('beforeunload', () => {
    if (refreshHandle) clearInterval(refreshHandle);
  });
})();
