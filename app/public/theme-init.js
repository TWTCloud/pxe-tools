(() => {
  'use strict';
  const root = document.documentElement;
  let savedTheme;
  let sidebarCollapsed;
  try {
    savedTheme = localStorage.getItem('theme');
    sidebarCollapsed = localStorage.getItem('pxe.sidebar.collapsed');
  } catch (_) {
    // A blocked storage must not prevent the default theme from being applied.
  }
  const mode = ['light', 'dark', 'system'].includes(savedTheme) ? savedTheme : 'light';
  root.dataset.themeMode = mode;
  root.dataset.theme = mode === 'system' && matchMedia('(prefers-color-scheme: dark)').matches
    ? 'dark' : mode === 'system' ? 'light' : mode;
  root.dataset.sidebarCollapsed = sidebarCollapsed === 'true' ? 'true' : 'false';
})();
