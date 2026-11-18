// The stylesheet follows the system appearance immediately; IndexedDB applies an
// explicitly chosen appearance as soon as it is available, on app and legal pages.
import { loadTheme } from './storage.js';
const initialTheme = document.documentElement.dataset.theme;
void loadTheme().then((theme) => {
  // Do not overwrite a choice the user/app has already applied while storage opened.
  if (document.documentElement.dataset.theme !== initialTheme) return;
  if (theme === 'light' || theme === 'dark') document.documentElement.dataset.theme = theme;
});
