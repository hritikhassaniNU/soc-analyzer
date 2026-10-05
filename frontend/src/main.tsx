import './lib/theme.ts' // first: set light/dark before anything renders
import { QueryClientProvider } from '@tanstack/react-query'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router'
import App from './App.tsx'
import { queryClient } from './lib/queryClient.ts'
import './index.css'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    {/* Server state (API data): caching, retries, polling */}
    <QueryClientProvider client={queryClient}>
      {/* URL -> page */}
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
)
