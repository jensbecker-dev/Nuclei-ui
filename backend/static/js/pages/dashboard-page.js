(() => {
  let chart = null;
  const CHART_CACHE_KEY = 'nuclei_dashboard_severity_chart_cache_v1';
  let lastCompletedSignature = null;

  function esc(value) {
    return String(value ?? '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#039;');
  }

  function timeAgo(isoString) {
    if (!isoString) return '-';
    const delta = Math.floor((Date.now() - new Date(isoString).getTime()) / 1000);
    if (delta < 60) return `${Math.max(delta, 1)}s ago`;
    if (delta < 3600) return `${Math.floor(delta / 60)}m ago`;
    if (delta < 86400) return `${Math.floor(delta / 3600)}h ago`;
    return `${Math.floor(delta / 86400)}d ago`;
  }

  function renderRecentScans(scans) {
    const body = document.getElementById('dashboard-scans-body');
    if (!body) return;

    body.innerHTML = '';
    const rows = scans || [];

    if (!rows.length) {
      body.innerHTML = '<tr><td colspan="6" class="px-3 py-4 text-sm text-slate-500">No scans yet. Start your first scan from the Scans page.</td></tr>';
      return;
    }

    for (const scan of rows.slice(0, 10)) {
      const tr = document.createElement('tr');
      tr.className = 'border-t border-slate-200 dark:border-slate-800';
      tr.innerHTML = `
        <td class="px-3 py-2">${scan.id}</td>
        <td class="px-3 py-2 max-w-[260px] truncate" title="${esc(scan.target)}">${esc(scan.target)}</td>
        <td class="px-3 py-2">${esc(scan.status)}</td>
        <td class="px-3 py-2">${scan.findingsCount ?? 0}</td>
        <td class="px-3 py-2">${scan.criticalCount ?? 0} / ${scan.highCount ?? 0}</td>
        <td class="px-3 py-2 text-xs text-slate-500 dark:text-slate-400">${timeAgo(scan.updatedAt)}</td>
      `;
      body.appendChild(tr);
    }
  }

  function getCompletedSignature(summary) {
    const recent = summary?.recentScans || [];
    const completed = recent.filter((scan) => String(scan.status || '').toLowerCase() === 'completed');
    if (!completed.length) return 'none';
    return completed.map((scan) => `${scan.id}:${scan.updatedAt || ''}`).join('|');
  }

  function loadCachedChart() {
    try {
      const raw = localStorage.getItem(CHART_CACHE_KEY);
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      if (!parsed || typeof parsed !== 'object') return null;
      return parsed;
    } catch {
      return null;
    }
  }

  function saveCachedChart(signature, severityTotals) {
    try {
      localStorage.setItem(CHART_CACHE_KEY, JSON.stringify({ signature, severityTotals }));
    } catch {
      // ignore localStorage quota/runtime issues
    }
  }

  async function loadSummary() {
    const summaryRes = await fetch('/api/dashboard/summary');

    if (!summaryRes.ok) return;

    const summary = await summaryRes.json();
    document.getElementById('sum-total-scans').textContent = summary.totalScans ?? 0;
    document.getElementById('sum-open-findings').textContent = summary.lifecycleTotals?.open ?? 0;
    document.getElementById('sum-overdue').textContent = summary.overdueOpenFindings ?? 0;
    document.getElementById('sum-sla').textContent = `${summary.slaCompliancePct ?? 0}%`;
    renderRecentScans(summary.recentScans || []);

    const signature = getCompletedSignature(summary);
    const cached = loadCachedChart();
    const completedChanged = signature !== lastCompletedSignature;

    // If no completed scan exists yet, keep existing persistent chart (if available) for stable UX.
    if (signature === 'none' && cached?.severityTotals) {
      renderChart(cached.severityTotals);
      return;
    }

    // Reuse cached chart if completed scan signature did not change.
    if (!completedChanged && cached && cached.signature === signature && cached.severityTotals) {
      renderChart(cached.severityTotals);
      lastCompletedSignature = signature;
      return;
    }

    const findingsRes = await fetch('/api/findings?limit=500');
    let severityTotals = summary.severityTotals || { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

    if (findingsRes.ok) {
      const findingsData = await findingsRes.json();
      severityTotals = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      for (const f of findingsData.findings || []) {
        const sev = (f.severity || 'info').toLowerCase();
        severityTotals[sev] = (severityTotals[sev] || 0) + 1;
      }
    }

    saveCachedChart(signature, severityTotals);
    renderChart(severityTotals);
    lastCompletedSignature = signature;
  }

  async function loadHealth() {
    const res = await fetch('/api/health');
    if (!res.ok) return;
    const health = await res.json();
    document.getElementById('health-version').textContent = health.nucleiInstalled ? health.nucleiVersion : 'Nuclei runtime not available';
  }

  function renderChart(severityTotals) {
    const canvas = document.getElementById('severityChart');
    if (!canvas || !window.Chart) return;

    const isDark = document.documentElement.classList.contains('dark');
    const axisColor = isDark ? 'rgba(148, 163, 184, 0.75)' : 'rgba(71, 85, 105, 0.75)';
    const gridColor = isDark ? 'rgba(71, 85, 105, 0.22)' : 'rgba(148, 163, 184, 0.22)';

    const values = [
      severityTotals.critical || 0,
      severityTotals.high || 0,
      severityTotals.medium || 0,
      severityTotals.low || 0,
      severityTotals.info || 0,
    ];

    if (chart) chart.destroy();

    chart = new Chart(canvas, {
      type: 'bar',
      data: {
        labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
        datasets: [{
          data: values,
          backgroundColor: ['#dc2626', '#f97316', '#eab308', '#22c55e', '#06b6d4'],
          borderRadius: 10,
          maxBarThickness: 44,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            displayColors: false,
            backgroundColor: isDark ? 'rgba(15, 23, 42, 0.92)' : 'rgba(15, 23, 42, 0.88)',
            titleColor: '#e2e8f0',
            bodyColor: '#e2e8f0',
            padding: 10,
          },
        },
        scales: {
          x: {
            ticks: { color: axisColor },
            grid: { color: gridColor },
          },
          y: {
            beginAtZero: true,
            ticks: { color: axisColor, precision: 0 },
            grid: { color: gridColor },
          },
        },
      },
    });
  }

  loadSummary();
  loadHealth();
  setInterval(loadSummary, 5000);
})();
