import { useState, useEffect } from 'react'
import ServiceCard from './ServiceCard'
import '../styles/Dashboard.css'

const DEFAULT_SERVICES = [
  { id: 'ssh-1',   type: 'ssh',   name: 'SSH Server 1',   port: 2222, persistent: true },
  { id: 'ssh-2',   type: 'ssh',   name: 'SSH Server 2',   port: 2223, persistent: true },
  { id: 'http-1',  type: 'http',  name: 'HTTP Server 1',  port: 8081, persistent: true },
  { id: 'http-2',  type: 'http',  name: 'HTTP Server 2',  port: 8082, persistent: true },
  { id: 'mysql-1', type: 'mysql', name: 'MySQL Server 1', port: 3307, persistent: true },
  { id: 'mysql-2', type: 'mysql', name: 'MySQL Server 2', port: 3308, persistent: true },
]

export default function Dashboard({ onLogout, api }) {
  const [services, setServices] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadServices()
    const interval = setInterval(loadServices, 5000)
    return () => clearInterval(interval)
  }, [])

  const loadServices = async () => {
    try {
      const res = await api.get('/api/services')
      // El nuevo services.py devuelve array directo; el viejo devolvía { count, services: [] }
      const servicesList = Array.isArray(res.data) ? res.data : (res.data.services || [])
      const activeMap = {}
      servicesList.forEach(s => { activeMap[s.id] = s })

      const defaultIds = new Set(DEFAULT_SERVICES.map(s => s.id))
      const extras = servicesList.filter(s => !defaultIds.has(s.id))

      const merged = DEFAULT_SERVICES.map(d => {
        const active = activeMap[d.id]
        if (active) return { ...d, ...active }
        return { ...d, status: 'none' }
      })

      setServices([...merged, ...extras])
    } catch {
      setServices(DEFAULT_SERVICES.map(d => ({ ...d, status: 'none' })))
    } finally {
      setLoading(false)
    }
  }

  const handleAction = async (action, serviceId, data = {}) => {
    try {
      switch (action) {
        case 'create': {
          // Este caso ya no se usa: el flujo de creación pasa siempre por
          // EditConfigModal → handleSaveConfig en ServiceCard → POST /api/services
          // Se deja por compatibilidad pero no debería llegar aquí.
          break
        }
        case 'save': {
          const service = services.find(s => s.id === serviceId)
          if (!service) return
          const { port, persistent, config } = data
          const body = { port, persistent, config }

          // Si el contenedor está activo (running o paused), usar reconfigure para recrearlo
          if (service.docker_container_id && (service.status === 'running' || service.status === 'paused')) {
            await api.patch(`/api/services/${serviceId}/reconfigure`, body)
          } else {
            // Guardar configuración y lanzar (si no existe o está detenido)
            await api.post(`/api/services/${serviceId}/setup-config`, {
              type: service.type,
              replica_id: parseInt(service.id.split('-')[1]),
              port,
              persistent,
              config
            })
            // Si estaba detenido o es nuevo, lanzar el contenedor
            await api.post(`/api/services/${serviceId}/launch`)
          }
          break
        }
        case 'launch':
          await api.post(`/api/services/${serviceId}/launch`, {})
          break
        case 'recreate':
          await api.post(`/api/services/${serviceId}/recreate`, {})
          break
        case 'stop':
          await api.patch(`/api/services/${serviceId}/stop`, {})
          break
        case 'start':
          await api.patch(`/api/services/${serviceId}/start`, {})
          break
        case 'delete':
          await api.delete(`/api/services/${serviceId}`)
          break
        default:
          break
      }
      await loadServices()
    } catch (err) {
      console.error(`Error on action ${action}:`, err)
      alert(err.response?.data?.detail || `Error: ${action}`)
    }
  }

  if (loading) return <div className="loading">Loading...</div>

  return (
    <div className="dashboard">
      <header className="header">
        <h1>🛡️ Honeypot Manager</h1>
        <button onClick={onLogout} className="logout-btn">Logout</button>
      </header>

      <main className="content">
        <div className="services-container">
          <h2>Honeypot Services</h2>
          <div className="service-grid">
            {services.map(service => (
              <ServiceCard
                key={service.id}
                service={service}
                api={api}
                onAction={(action, data) => handleAction(action, service.id, data)}
                onLogsRefresh={loadServices}
              />
            ))}
          </div>
        </div>
      </main>
    </div>
  )
}