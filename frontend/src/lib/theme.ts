/**
 * Follow the operating system's light/dark setting by toggling shadcn's `.dark` class on <html>.
 * Imported first in main.tsx (a module, not an inline <script>, so a strict CSP stays possible).
 */
const darkQuery = window.matchMedia('(prefers-color-scheme: dark)')

function applyTheme() {
  document.documentElement.classList.toggle('dark', darkQuery.matches)
}

applyTheme()
darkQuery.addEventListener('change', applyTheme) // user switches OS theme while the app is open
