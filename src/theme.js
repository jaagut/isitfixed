// Classic script loaded synchronously in <head>: applies the saved appearance before the
// first paint so a forced light or dark theme does not flash. app.js keeps it in sync.
try {
  const theme = JSON.parse(localStorage.getItem('cve-desk-v1') || 'null')?.theme;
  if (theme === 'light' || theme === 'dark') document.documentElement.dataset.theme = theme;
} catch {
  /* No saved workspace or storage unavailable: follow the system setting. */
}
