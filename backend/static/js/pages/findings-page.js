(() => {
  const tbody = document.getElementById('findings-table-body');
  const statusFilter = document.getElementById('filter-status');
  const severityFilter = document.getElementById('filter-severity');
  const modal = document.getElementById('finding-detail-modal');
  const closeBtn = document.getElementById('close-finding-modal');
  const detailContent = document.getElementById('finding-detail-content');

  function renderRefLinks(refs) {
    if (!refs || !refs.length) return '<span class="text-slate-400">-</span>';
    return refs.map((r) => `<a href="${r}" target="_blank" rel="noopener" class="text-brand-600 hover:underline dark:text-brand-300">${r}</a>`).join('<br>');
  }

  async function loadFindings() {
    const params = new URLSearchParams({ limit: '200' });
    if (statusFilter.value) params.set('status', statusFilter.value);
    if (severityFilter.value) params.set('severity', severityFilter.value);

    const res = await fetch(`/api/findings?${params.toString()}`);
    if (!res.ok) return;
    const data = await res.json();

    tbody.innerHTML = '';
    for (const finding of data.findings || []) {
      const cve = (finding.cveIds && finding.cveIds.length) ? finding.cveIds[0] : '-';
      const tr = document.createElement('tr');
      tr.className = 'border-t border-slate-200 dark:border-slate-800';
      tr.innerHTML = `
        <td class="px-3 py-2">${finding.id}</td>
        <td class="px-3 py-2">${finding.severity || 'info'}</td>
        <td class="px-3 py-2">${cve}</td>
        <td class="px-3 py-2">${finding.cvssScore ?? '-'}</td>
        <td class="px-3 py-2 max-w-[220px] truncate" title="${finding.templateName || finding.templateId || '-'}">${finding.templateName || finding.templateId || '-'}</td>
        <td class="px-3 py-2">${finding.host || '-'}</td>
        <td class="px-3 py-2">${finding.status}</td>
        <td class="px-3 py-2"><button data-finding-id="${finding.id}" class="open-finding rounded-lg border border-slate-300 px-2.5 py-1 text-xs hover:bg-slate-100 dark:border-slate-700 dark:hover:bg-slate-800">Details</button></td>
      `;
      tbody.appendChild(tr);
    }

    document.querySelectorAll('.open-finding').forEach((btn) => {
      btn.addEventListener('click', () => openDetail(Number(btn.dataset.findingId)));
    });
  }

  async function openDetail(findingId) {
    const res = await fetch(`/api/findings/${findingId}`);
    if (!res.ok) return;
    const data = await res.json();
    const f = data.finding;

    detailContent.innerHTML = `
      <div class="grid grid-cols-1 gap-3 md:grid-cols-2">
        <p><span class="font-medium">Severity:</span> ${f.severity || '-'}</p>
        <p><span class="font-medium">CVE IDs:</span> ${(f.cveIds || []).join(', ') || '-'}</p>
        <p><span class="font-medium">CVSS:</span> ${f.cvssScore ?? '-'}</p>
        <p><span class="font-medium">CVSS Metrics:</span> ${f.cvssMetrics || '-'}</p>
        <p><span class="font-medium">Template:</span> ${f.templateName || f.templateId || '-'}</p>
        <p><span class="font-medium">Matched URL:</span> ${f.matchedUrl || f.matchedAt || '-'}</p>
      </div>
      <div>
        <p class="font-medium">Description</p>
        <p class="text-slate-600 dark:text-slate-300">${f.description || '-'}</p>
      </div>
      <div>
        <p class="font-medium">References</p>
        <div class="text-sm">${renderRefLinks(f.references || [])}</div>
      </div>
      <details>
        <summary class="cursor-pointer font-medium">Raw Payload</summary>
        <pre class="mt-2 max-h-64 overflow-auto rounded-lg border border-slate-200 p-3 text-xs dark:border-slate-700">${JSON.stringify(f.rawPayload || {}, null, 2)}</pre>
      </details>
    `;

    modal.classList.remove('hidden');
    modal.classList.add('flex');
  }

  closeBtn.addEventListener('click', () => {
    modal.classList.add('hidden');
    modal.classList.remove('flex');
  });

  statusFilter.addEventListener('change', loadFindings);
  severityFilter.addEventListener('change', loadFindings);

  loadFindings();
})();
