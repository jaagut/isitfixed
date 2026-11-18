// Classic script loaded synchronously in <head> (app and legal pages): applies the saved
// appearance before the first paint so a forced light or dark theme does not flash.
// app.js keeps the 'cve-desk-theme' key in sync; saves from before it existed only have
// the theme inside the workspace, which is read once until app.js writes the key.
try {
  let theme = localStorage.getItem('cve-desk-theme');
  if (theme === null) theme = JSON.parse(localStorage.getItem('cve-desk-v1') || 'null')?.theme;
  if (theme === 'light' || theme === 'dark') document.documentElement.dataset.theme = theme;
} catch {
  /* No saved theme or storage unavailable: follow the system setting. */
}
