(() => {
  const list = document.getElementById('workflow-list');
  const openEl = document.getElementById('wf-open');
  const progressEl = document.getElementById('wf-progress');
  const acceptedEl = document.getElementById('wf-accepted');
  const resolvedEl = document.getElementById('wf-resolved');
  const purgeScansBtn = document.getElementById('purge-scans-btn');
  const purgeFindingsBtn = document.getElementById('purge-findings-btn');
  const purgeDatabaseBtn = document.getElementById('purge-database-btn');
  const purgeFlash = document.getElementById('purge-flash');

  function setPurgeFlash(message, isError = false) {
    if (!purgeFlash) return;
    purgeFlash.textContent = message;
    purgeFlash.className = `mt-3 text-sm ${isError ? 'text-rose-600 dark:text-rose-400' : 'text-emerald-600 dark:text-emerald-400'}`;
  }

  async function loadWorkflow() {
    const res = await fetch('/api/findings?limit=300');
    if (!res.ok) return;
    const data = await res.json();
    const findings = data.findings || [];

    const counts = { open: 0, in_progress: 0, accepted_risk: 0, resolved: 0 };
    for (const f of findings) {
      const key = counts[f.status] !== undefined ? f.status : 'open';
      counts[key] += 1;
    }

    openEl.textContent = counts.open;
    progressEl.textContent = counts.in_progress;
    acceptedEl.textContent = counts.accepted_risk;
    resolvedEl.textContent = counts.resolved;

    list.innerHTML = findings.slice(0, 20).map((f) => `
      <div class="rounded-xl border border-slate-200 bg-white p-3 dark:border-slate-700 dark:bg-slate-900">
        <div class="flex flex-wrap items-center justify-between gap-2">
          <p class="font-medium">#${f.id} · ${f.templateName || f.templateId || 'Nuclei Result'}</p>
          <span class="text-xs text-slate-500">${f.status}</span>
        </div>
        <p class="mt-1 text-xs text-slate-500">Host: ${f.host || '-'} · Severity: ${f.severity || 'info'} · CVE: ${(f.cveIds || []).join(', ') || '-'}</p>
      </div>
    `).join('');

    if (!findings.length) {
      list.innerHTML = '<p class="text-sm text-slate-500">No manually promoted findings yet. Start a scan and promote approved results to build your triage pipeline.</p>';
    }
  }

  loadWorkflow();
  setInterval(loadWorkflow, 7000);

  async function executePurge(endpoint, confirmText) {
    const ok = window.confirm(confirmText);
    if (!ok) return;

    try {
      const res = await fetch(endpoint, { method: 'DELETE' });
      const data = await res.json();
      if (!res.ok) {
        setPurgeFlash(data.error || 'Delete operation failed.', true);
        return;
      }

      setPurgeFlash('Delete operation completed successfully.');
      await loadWorkflow();
    } catch (err) {
      setPurgeFlash(String(err), true);
    }
  }

  purgeScansBtn?.addEventListener('click', () => executePurge('/api/admin/purge/scans', 'Delete all scans for this tenant? This cannot be undone.'));
  purgeFindingsBtn?.addEventListener('click', () => executePurge('/api/admin/purge/findings', 'Delete all findings for this tenant? This cannot be undone.'));
  purgeDatabaseBtn?.addEventListener('click', () => executePurge('/api/admin/purge/database', 'Delete ALL database values (tenant scope)? This cannot be undone.'));
})();
