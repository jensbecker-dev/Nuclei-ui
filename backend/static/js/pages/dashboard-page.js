(() => {
  let chart = null;

  async function loadSummary() {
    const [summaryRes, findingsRes] = await Promise.all([
      fetch('/api/dashboard/summary'),
      fetch('/api/findings?limit=500'),
    ]);

    if (!summaryRes.ok) return;

    const summary = await summaryRes.json();
    document.getElementById('sum-total-scans').textContent = summary.totalScans ?? 0;
    document.getElementById('sum-open-findings').textContent = summary.lifecycleTotals?.open ?? 0;
    document.getElementById('sum-overdue').textContent = summary.overdueOpenFindings ?? 0;
    document.getElementById('sum-sla').textContent = `${summary.slaCompliancePct ?? 0}%`;

    let severityTotals = summary.severityTotals || { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

    if (findingsRes.ok) {
      const findingsData = await findingsRes.json();
      severityTotals = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      for (const f of findingsData.findings || []) {
        const sev = (f.severity || 'info').toLowerCase();
        severityTotals[sev] = (severityTotals[sev] || 0) + 1;
      }
    }

    renderChart(severityTotals);
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
})();
