// FILE: src/main.tsx

import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Routes, Route } from 'react-router'
import './index.css'
import Layout  from './components/Layout'
import Home    from './pages/Home'
import Scan    from './pages/Scan'
import History from './pages/History'
import About   from './pages/About'
import Admin   from './pages/Admin'
import SIEM    from './pages/SIEM'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/"        element={<Home    />} />
          <Route path="/scan"    element={<Scan    />} />
          <Route path="/history" element={<History />} />
          <Route path="/about"   element={<About   />} />
          <Route path="/admin"   element={<Admin   />} />
          <Route path="/siem"    element={<SIEM    />} />
        </Route>
      </Routes>
    </BrowserRouter>
  </StrictMode>,
)