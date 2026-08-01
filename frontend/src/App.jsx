import { useState, useEffect } from 'react'
import axios from 'axios'
import Login from './components/Login'
import Setup from './components/Setup'
import Dashboard from './components/Dashboard'
import './App.css'

const API = axios.create({
  baseURL: '',  // ← vacío: las peticiones se harán a la misma ruta base
  withCredentials: true
})

function App() {
  const [stage, setStage] = useState('checking') // checking|setup|login|dashboard
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    checkSetup()
  }, [])

  const checkSetup = async () => {
    try {
      const res = await API.get('/api/auth/check')
      if (res.data.setup_required) {
        setStage('setup')
      } else if (res.data.authenticated) {
        setStage('dashboard')
      } else {
        setStage('login')
      }
    } catch (err) {
      console.error('Error checking setup:', err)
      setStage('login')
    } finally {
      setLoading(false)
    }
  }

  const handleSetupComplete = () => {
    // Backend establece cookie automáticamente
    // Recargar para que checkSetup() verifique de nuevo
    setStage('login')
  }

  const handleLoginComplete = () => {
    // Backend establece cookie automáticamente
    // Recargar para que checkSetup() verifique de nuevo
    setStage('dashboard')
  }

  const handleLogout = async () => {
    try {
      await API.post('/api/auth/logout')
    } catch (err) {
      console.error('Error logging out:', err)
    } finally {
      // Cookie se elimina automáticamente
      setStage('login')
    }
  }

  if (loading) {
    return <div style={{ textAlign: 'center', marginTop: '50px', color: 'var(--cyan)' }}>Loading...</div>
  }

  return (
    <div className="app">
      {stage === 'setup' && <Setup onComplete={handleSetupComplete} api={API} />}
      {stage === 'login' && <Login onComplete={handleLoginComplete} api={API} />}
      {stage === 'dashboard' && <Dashboard onLogout={handleLogout} api={API} />}
    </div>
  )
}

export default App