const { createApp } = Vue;

createApp({
  delimiters: ['[[', ']]'],
  data() {
    return {
      sidebarCollapsed: localStorage.getItem('sidebarCollapsed') === 'true',
      mobileSidebarOpen: false,
      activeNav: 'dashboard',
      navItems: [
        { id: 'dashboard', href: '#', icon: 'DB', label: 'Dashboard', hint: 'KPIs & Health' },
        { id: 'scans', href: '#scans', icon: 'SC', label: 'Scans', hint: 'Scan Control Center' },
        { id: 'findings', href: '#findings', icon: 'FI', label: 'Findings', hint: 'CVE Intelligence' },
        { id: 'workflow', href: '#settings', icon: 'WF', label: 'Workflow', hint: 'Triage Pipeline' },
      ],
      isDark: document.documentElement.classList.contains('dark'),
      isSubmitting: false,
      flash: '',
      flashType: 'ok',
      templates: [],
      me: {
        role: '',
        tenantId: '',
      },
      findings: [],
      selectedFinding: null,
      findingDetailOpen: false,
      selectedScan: null,
      scanDetailOpen: false,
      findingFilter: {
        status: '',
        severity: '',
      },
      health: {
        nucleiInstalled: false,
        nucleiVersion: 'n/a',
      },
      summary: {
        totalScans: 0,
        runningScans: 0,
        failedScans: 0,
        severityTotals: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        lifecycleTotals: { open: 0, in_progress: 0, accepted_risk: 0, resolved: 0 },
        overdueOpenFindings: 0,
        slaCompliancePct: 0,
        recentScans: [],
      },
      form: {
        target: '',
        template: '',
        severity: '',
        tags: '',
        advancedArgs: '',
      },
      chart: null,
      pollHandle: null,
    };
  },
  methods: {
    goDashboard() {
      window.location.href = '/dashboard';
    },
    async switchToMultipageIfAvailable() {
      try {
        const checks = await Promise.all([
          fetch('/scans', { method: 'GET' }),
          fetch('/findings', { method: 'GET' }),
          fetch('/workflow', { method: 'GET' }),
        ]);

        const allAvailable = checks.every((res) => res.ok);
        if (!allAvailable) return;

        this.navItems = [
          { id: 'dashboard', href: '/dashboard', icon: 'DB', label: 'Dashboard', hint: 'KPIs & Health' },
          { id: 'scans', href: '/scans', icon: 'SC', label: 'Scans', hint: 'Scan Control Center' },
          { id: 'findings', href: '/findings', icon: 'FI', label: 'Findings', hint: 'CVE Intelligence' },
          { id: 'workflow', href: '/workflow', icon: 'WF', label: 'Workflow', hint: 'Triage Pipeline' },
        ];
      } catch {
        // Keep fallback on single-page navigation
      }
    },
    toggleSidebar() {
      this.sidebarCollapsed = !this.sidebarCollapsed;
      localStorage.setItem('sidebarCollapsed', String(this.sidebarCollapsed));
    },
    onMenuClick(itemId) {
      if (itemId) {
        this.activeNav = itemId;
        const target = this.navItems.find((item) => item.id === itemId);
        if (target?.href) {
          window.location.href = target.href;
          return;
        }
      }
      if (window.innerWidth < 768) {
        this.mobileSidebarOpen = false;
      }
    },
    onResize() {
      if (window.innerWidth >= 768) {
        this.mobileSidebarOpen = false;
      }
    },
    toggleTheme() {
      this.isDark = !this.isDark;
      document.documentElement.classList.toggle('dark', this.isDark);
      localStorage.setItem('theme', this.isDark ? 'dark' : 'light');
    },
    async fetchHealth() {
      const res = await fetch('/api/health');
      this.health = await res.json();
    },
    async fetchMe() {
      const res = await fetch('/api/me');
      if (!res.ok) return;
      this.me = await res.json();
    },
    async fetchTemplates() {
      const res = await fetch('/api/templates');
      if (!res.ok) {
        return;
      }
      const data = await res.json();
      this.templates = data.templates || [];
    },
    async fetchSummary() {
      const res = await fetch('/api/dashboard/summary');
      if (!res.ok) return;
      this.summary = await res.json();
      this.renderChart();
    },
    async fetchFindings() {
      const params = new URLSearchParams({ limit: '50' });
      if (this.findingFilter.status) params.set('status', this.findingFilter.status);
      if (this.findingFilter.severity) params.set('severity', this.findingFilter.severity);

      const res = await fetch(`/api/findings?${params.toString()}`);
      if (!res.ok) {
        return;
      }
      const data = await res.json();
      this.findings = (data.findings || []).map((f) => ({
        ...f,
        dueAt: this.toDateTimeLocalValue(f.dueAt),
      }));
    },
    async startScan() {
      this.flash = '';
      this.isSubmitting = true;
      try {
        const res = await fetch('/api/scans', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(this.form),
        });
        const data = await res.json();

        if (!res.ok) {
          this.flash = data.error || 'Scan could not be started';
          this.flashType = 'error';
          return;
        }

        this.flash = `Scan #${data.scan.id} started.`;
        this.flashType = 'ok';
        await Promise.all([this.fetchSummary(), this.fetchFindings()]);
      } catch (err) {
        this.flash = String(err);
        this.flashType = 'error';
      } finally {
        this.isSubmitting = false;
      }
    },
    renderChart() {
      const canvas = document.getElementById('severityChart');
      if (!canvas || !window.Chart) {
        return;
      }

      const data = this.summary.severityTotals;
      const values = [data.critical, data.high, data.medium, data.low, data.info];

      if (this.chart) {
        this.chart.destroy();
      }

      this.chart = new Chart(canvas, {
        type: 'bar',
        data: {
          labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
          datasets: [
            {
              label: 'Findings',
              data: values,
              borderWidth: 1,
              backgroundColor: ['#dc2626', '#f97316', '#eab308', '#22c55e', '#06b6d4'],
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            y: {
              beginAtZero: true,
              ticks: { precision: 0 },
            },
          },
          plugins: {
            legend: {
              display: false,
            },
          },
        },
      });
    },
    formatDate(isoDate) {
      return new Date(isoDate).toLocaleString();
    },
    toDateTimeLocalValue(value) {
      if (!value) return '';
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) return '';
      const pad = (n) => String(n).padStart(2, '0');
      return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
    },
    async saveFinding(finding) {
      try {
        const payload = {
          status: finding.status,
          owner: finding.owner || null,
          dueAt: finding.dueAt ? new Date(finding.dueAt).toISOString() : null,
          triageNote: finding.triageNote || null,
        };

        const res = await fetch(`/api/findings/${finding.id}`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });

        const data = await res.json();
        if (!res.ok) {
          this.flash = data.error || 'Finding could not be updated';
          this.flashType = 'error';
          return;
        }

        this.flash = `Finding #${finding.id} updated.`;
        this.flashType = 'ok';
        await Promise.all([this.fetchSummary(), this.fetchFindings()]);
      } catch (err) {
        this.flash = String(err);
        this.flashType = 'error';
      }
    },
    async openFindingDetails(findingId) {
      try {
        const res = await fetch(`/api/findings/${findingId}`);
        const data = await res.json();
        if (!res.ok) {
          this.flash = data.error || 'Details could not be loaded';
          this.flashType = 'error';
          return;
        }
        this.selectedFinding = data.finding;
        this.findingDetailOpen = true;
      } catch (err) {
        this.flash = String(err);
        this.flashType = 'error';
      }
    },
    async openScanDetails(scanId) {
      try {
        const res = await fetch(`/api/scans/${scanId}`);
        const data = await res.json();
        if (!res.ok) {
          this.flash = data.error || 'Scan details could not be loaded';
          this.flashType = 'error';
          return;
        }
        this.selectedScan = data;
        this.scanDetailOpen = true;
      } catch (err) {
        this.flash = String(err);
        this.flashType = 'error';
      }
    },
    formatJson(value) {
      try {
        return JSON.stringify(value ?? {}, null, 2);
      } catch {
        return '{}';
      }
    },
    onScroll() {},
  },
  async mounted() {
    await this.switchToMultipageIfAvailable();
    await Promise.all([this.fetchHealth(), this.fetchMe(), this.fetchTemplates(), this.fetchSummary(), this.fetchFindings()]);
    this.pollHandle = setInterval(() => {
      this.fetchSummary();
      this.fetchFindings();
    }, 5000);
    this.onResize();
    this.onScroll();
    window.addEventListener('resize', this.onResize, { passive: true });
    window.addEventListener('scroll', this.onScroll, { passive: true });
  },
  beforeUnmount() {
    if (this.pollHandle) clearInterval(this.pollHandle);
    if (this.chart) this.chart.destroy();
    window.removeEventListener('resize', this.onResize);
    window.removeEventListener('scroll', this.onScroll);
  },
}).mount('#app');
