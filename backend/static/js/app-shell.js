(() => {
  const sidebar = document.getElementById('app-sidebar');
  const spacer = document.getElementById('sidebar-spacer');
  const overlay = document.getElementById('sidebar-overlay');
  const toggleBtn = document.getElementById('sidebar-toggle');
  const toggleLeft = document.getElementById('sidebar-toggle-left');
  const toggleIcon = document.getElementById('sidebar-toggle-icon');
  const toggleRight = document.getElementById('sidebar-toggle-right');
  const mobileOpenBtn = document.getElementById('mobile-menu-open');
  const brand = document.getElementById('sidebar-brand');
  const themeToggle = document.getElementById('theme-toggle');
  const themeIcon = document.getElementById('theme-icon');

  if (!sidebar || !toggleBtn || !spacer) return;

  let collapsed = localStorage.getItem('sidebarCollapsed') === 'true';

  const navItems = document.querySelectorAll('.app-nav-item');
  const navTexts = document.querySelectorAll('.app-nav-text');

  function setThemeLabel() {
    const isDark = document.documentElement.classList.contains('dark');
    if (themeIcon) themeIcon.textContent = isDark ? '🌙' : '☀️';
    const label = document.getElementById('theme-label');
    if (label) label.textContent = isDark ? 'Dark mode active' : 'Light mode active';
  }

  function applyState() {
    if (collapsed) {
      sidebar.classList.remove('w-[19rem]');
      sidebar.classList.add('w-[5.6rem]', 'sidebar-collapsed');
      spacer.classList.remove('md:w-[19rem]');
      spacer.classList.add('md:w-[5.6rem]');
      toggleLeft.textContent = 'Expand navigation';
      if (toggleRight) toggleRight.textContent = '';
      toggleIcon.textContent = '▶';
      toggleBtn.classList.remove('grid-cols-[1fr_auto_1fr]', 'px-3');
      toggleBtn.classList.add('place-content-center');
      brand?.classList.add('hidden');
      navTexts.forEach((el) => el.classList.add('hidden'));
      navItems.forEach((item) => item.classList.add('justify-center'));
    } else {
      sidebar.classList.remove('w-[5.6rem]', 'sidebar-collapsed');
      sidebar.classList.add('w-[19rem]');
      spacer.classList.remove('md:w-[5.6rem]');
      spacer.classList.add('md:w-[19rem]');
      toggleLeft.textContent = 'Collapse navigation';
      if (toggleRight) toggleRight.textContent = 'Layout';
      toggleIcon.textContent = '◀';
      toggleBtn.classList.remove('place-content-center');
      toggleBtn.classList.add('grid-cols-[1fr_auto_1fr]', 'px-3');
      brand?.classList.remove('hidden');
      navTexts.forEach((el) => el.classList.remove('hidden'));
      navItems.forEach((item) => item.classList.remove('justify-center'));
    }
  }

  toggleBtn.addEventListener('click', () => {
    collapsed = !collapsed;
    localStorage.setItem('sidebarCollapsed', String(collapsed));
    applyState();
  });

  mobileOpenBtn?.addEventListener('click', () => {
    sidebar.classList.remove('-translate-x-full');
    overlay?.classList.remove('hidden');
  });

  overlay?.addEventListener('click', () => {
    sidebar.classList.add('-translate-x-full');
    overlay.classList.add('hidden');
  });

  themeToggle?.addEventListener('click', () => {
    const isDark = document.documentElement.classList.toggle('dark');
    localStorage.setItem('theme', isDark ? 'dark' : 'light');
    setThemeLabel();
  });

  setThemeLabel();
  applyState();
})();
