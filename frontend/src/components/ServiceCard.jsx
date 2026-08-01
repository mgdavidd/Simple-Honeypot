// ========== ServiceCard.jsx ==========
import { useState } from 'react'
import EditConfigModal from './EditConfigModal'
import LogsViewer from './LogsViewer'
import '../styles/ServiceCard.css'

export default function ServiceCard({ service, api, onAction, onLogsRefresh }) {
  const [showEditModal, setShowEditModal] = useState(false)
  const [showLogs, setShowLogs] = useState(false)

  const status = service.status || 'none'
  const isRunning = status === 'running'
  const isPaused = status === 'paused'
  const isConfigured = status === 'configured'
  const isDestroyed = status === 'destroyed' || status === 'stopped'
  const isNone = status === 'none'

  const getTypeIcon = (type) => ({ ssh: '🔌', http: '🌐', mysql: '🗄️' }[type] || '📦')

  const getStatusBadge = () => {
    const badges = {
      running:    <span className="status-badge status-running">● Running</span>,
      paused:     <span className="status-badge status-paused">⏸ Paused</span>,
      configured: <span className="status-badge status-configured">⚙ Configured</span>,
      destroyed:  <span className="status-badge status-stopped">⊘ Stopped</span>,
      none:       <span className="status-badge status-none">— Not Created</span>,
    }
    return badges[status] || badges.none
  }

  const handleSaveConfig = async (payload) => {
    const { port, persistent, config } = payload
    const isActiveContainer = status === 'running' || status === 'paused'
    const exists = status && status !== 'none'

    const requestBody = {
      type: service.type,
      replica_id: parseInt(service.id.split('-')[1]),
      port,
      persistent,
      config,
    }

    if (!exists) {
      // Servicio nuevo: crear y lanzar directamente
      await api.post('/api/services', requestBody)
    } else if (isActiveContainer) {
      // Contenedor corriendo o pausado: reconfigurar (destruye y recrea)
      await api.patch(`/api/services/${service.id}/reconfigure`, requestBody)
    } else {
      // Estado configured/destroyed/stopped: guardar config y lanzar
      await api.post(`/api/services/${service.id}/setup-config`, requestBody)
      await api.post(`/api/services/${service.id}/launch`)
    }
  }

  // Obtener el nombre de la plantilla (para MySQL y HTTP)
  const template = service.template || service.config?.template || "empty"

  return (
    <>
      <div className="service-card">
        <div className="card-header">
          <div className="service-title">
            <span className="type-icon">{getTypeIcon(service.type)}</span>
            <div>
              <h3>{service.name}</h3>
              <p className="service-id">{service.id}</p>
            </div>
          </div>
          {getStatusBadge()}
        </div>

        <div className="card-body">
          <div className="info-row">
            <span className="label">Port:</span>
            <span className="value">{service.port || '—'}</span>
          </div>
          <div className="info-row">
            <span className="label">Persistent:</span>
            <span className="value">{service.persistent ? '✓ Yes' : '✗ No'}</span>
          </div>
          {/* Mostrar plantilla si existe y el servicio es MySQL o HTTP */}
          {(service.type === 'mysql' || service.type === 'http') && template && (
            <div className="info-row">
              <span className="label">Template:</span>
              <span className="value">{template}</span>
            </div>
          )}
        </div>

        <div className="card-actions">
          {/* Config: siempre disponible */}
          <button className="btn btn-secondary" onClick={() => setShowEditModal(true)}>
            ⚙ Config
          </button>

          {/* Logs: siempre disponible */}
          <button className="btn btn-secondary" onClick={() => setShowLogs(true)}>
            📋 Logs
          </button>

          {/* Botones según estado */}
          {isNone && (
            <button
              className="btn btn-primary"
              onClick={() => setShowEditModal(true)}
            >
              ▶ Crear
            </button>
          )}

          {isConfigured && (
            <button
              className="btn btn-primary"
              onClick={() => onAction('launch')}
            >
              ▶ Lanzar
            </button>
          )}

          {isDestroyed && service.persistent && (
            <button
              className="btn btn-primary"
              onClick={() => onAction('recreate')}
            >
              ↺ Recrear
            </button>
          )}

          {isRunning && service.persistent && (
            <button
              className="btn btn-pause"
              onClick={() => onAction('stop')}
            >
              ⏸ Pausar
            </button>
          )}

          {isPaused && (
            <button
              className="btn btn-primary"
              onClick={() => onAction('start')}
            >
              ▶ Reanudar
            </button>
          )}

          {(isRunning || isPaused) && (
            <button
              className="btn btn-danger"
              onClick={() => window.confirm('¿Destruir este servicio?') && onAction('delete')}
            >
              🗑 Destruir
            </button>
          )}
        </div>
      </div>

      {showEditModal && (
        <EditConfigModal
          service={service}
          onClose={() => { setShowEditModal(false); onLogsRefresh() }}
          onSave={handleSaveConfig}
        />
      )}

      {showLogs && (
        <LogsViewer
          serviceId={service.id}
          serviceName={service.name}
          onClose={() => setShowLogs(false)}
          api={api}
          onRefresh={onLogsRefresh}
        />
      )}
    </>
  )
}