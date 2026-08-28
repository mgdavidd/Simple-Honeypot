import { useState, useEffect } from 'react'
import '../styles/LogsViewer.css'

// Tipos de query MySQL (excluyendo 'connect' y 'login_attempt')
const MYSQL_QUERY_TYPES = [
  'select', 'insert', 'update', 'delete', 'drop',
  'create', 'alter', 'use', 'show', 'describe', 'other'
]

// Patrones SQLi para filtro
const SQLI_PATTERNS = [
  { value: 'all', label: 'Todos los patrones' },
  { value: 'none', label: 'Sin SQLi' },
  { value: 'union_based', label: 'Union Based' },
  { value: 'time_based', label: 'Time Based' },
  { value: 'boolean_based', label: 'Boolean Based' },
  { value: 'error_based', label: 'Error Based' },
  { value: 'stacked_queries', label: 'Stacked Queries' },
  { value: 'comment_inject', label: 'Comment Injection' },
]

// Herramientas detectadas
const TOOL_OPTIONS = [
  { value: 'all', label: 'Todas las herramientas' },
  { value: 'none', label: 'Sin herramienta' },
  { value: 'sqlmap', label: 'sqlmap' },
  { value: 'havij', label: 'Havij' },
  { value: 'burp', label: 'Burp Suite' },
  { value: 'manual', label: 'Manual' },
]

// ── ActionBody: renderiza el body de cada action_label de forma legible ──────
function ActionBody({ label, body }) {
  if (!body || Object.keys(body).length === 0) return null

  // WordPress: guardó post
  if (label === 'wp_save_post') return (
    <div className="body-detail">
      {body.post_id    && <p>🆔 Post ID: <span className="highlight">#{body.post_id}</span></p>}
      {body.title      && <p>📌 Título: <span className="highlight">{body.title}</span></p>}
      {body.status     && <p>📄 Estado: <span className="highlight">{body.status}</span></p>}
      {body.author     && <p>👤 Autor: <span className="highlight">{body.author}</span></p>}
      {body.content_length !== undefined && (
        <p>📏 Longitud contenido: <span className="highlight">{body.content_length} chars</span></p>
      )}
      {body.content_preview && (
        <div className="body-preview">
          <p className="preview-label">Vista previa:</p>
          <p className="preview-text">{body.content_preview}</p>
        </div>
      )}
    </div>
  )

  // WordPress: eliminó post
  if (label === 'wp_delete_post') return (
    <div className="body-detail">
      {body.post_id && <p>🆔 Post eliminado: <span className="highlight">#{body.post_id}</span></p>}
    </div>
  )

  // WordPress: creó usuario
  if (label === 'wp_create_user') return (
    <div className="body-detail">
      {body.user_id  && <p>🆔 User ID: <span className="highlight">#{body.user_id}</span></p>}
      {body.username && <p>👤 Username: <span className="highlight">{body.username}</span></p>}
      {body.email    && <p>✉️ Email: <span className="highlight">{body.email}</span></p>}
      {body.role     && <p>🎭 Rol: <span className="highlight">{body.role}</span></p>}
      {body.name     && <p>📛 Nombre: <span className="highlight">{body.name}</span></p>}
    </div>
  )

  // WordPress: eliminó usuario
  if (label === 'wp_delete_user') return (
    <div className="body-detail">
      {body.user_id && <p>🆔 Usuario eliminado: <span className="highlight">#{body.user_id}</span></p>}
    </div>
  )

  // WordPress: cambió settings
  if (label === 'wp_save_options') return (
    <div className="body-detail">
      {body.count !== undefined && (
        <p>🔢 Campos modificados: <span className="highlight">{body.count}</span></p>
      )}
      {body.fields_changed?.length > 0 && (
        <p>🗝️ Campos: <span className="highlight">{body.fields_changed.join(', ')}</span></p>
      )}
      {body.values && Object.keys(body.values).length > 0 && (
        <div className="body-kv">
          {Object.entries(body.values).map(([k, v]) => (
            <div key={k} className="kv-row">
              <span className="kv-key">{k}</span>
              <span className="kv-val">{String(v)}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )

  // WordPress: XML-RPC
  if (label === 'wp_xmlrpc_call') return (
    <div className="body-detail">
      {body.method_hint && <p>📡 Método: <span className="highlight">{body.method_hint}</span></p>}
      {body.length      && <p>📏 Tamaño payload: <span className="highlight">{body.length} bytes</span></p>}
      {body.raw         && (
        <div className="body-preview">
          <p className="preview-label">Payload (primeros 500 chars):</p>
          <p className="preview-text">{body.raw}</p>
        </div>
      )}
    </div>
  )

  // PMA: SQL query (select, insert, update, delete, drop, create, alter, show, describe)
  if (label?.startsWith('pma_sql_')) return (
    <div className="body-detail">
      {body.db           && <p>🗄️ Base de datos: <span className="highlight">{body.db}</span></p>}
      {body.sql          && (
        <div className="body-preview">
          <p className="preview-label">SQL ejecutado:</p>
          <p className="preview-text sql-text">{body.sql}</p>
        </div>
      )}
      {body.rows_returned !== undefined && (
        <p>📊 Filas retornadas: <span className="highlight">{body.rows_returned}</span></p>
      )}
      {body.rows_affected !== undefined && body.rows_affected > 0 && (
        <p>⚡ Filas afectadas: <span className="highlight">{body.rows_affected}</span></p>
      )}
      {body.columns?.length > 0 && (
        <p>📋 Columnas: <span className="highlight">{body.columns.join(', ')}</span></p>
      )}
      {body.rows_preview?.length > 0 && (
        <div className="rows-preview">
          <p className="preview-label">Primeras filas:</p>
          <div style={{overflowX:'auto'}}>
            <table className="preview-table">
              <thead>
                <tr>{body.columns?.map(c => <th key={c}>{c}</th>)}</tr>
              </thead>
              <tbody>
                {body.rows_preview.map((row, i) => (
                  <tr key={i}>{(Array.isArray(row) ? row : [row]).map((cell, j) => (
                    <td key={j}>{cell === null ? <em style={{color:'#666'}}>NULL</em> : String(cell)}</td>
                  ))}</tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
      {body.error && <p className="body-error">⚠️ Error: <span>{body.error}</span></p>}
    </div>
  )

  // PMA: insert row
  if (label === 'pma_insert_row') return (
    <div className="body-detail">
      {body.table && <p>📋 Tabla: <span className="highlight">{body.table}</span></p>}
      {body.row && Object.keys(body.row).length > 0 && (
        <div className="body-kv">
          {Object.entries(body.row).map(([k, v]) => (
            <div key={k} className="kv-row">
              <span className="kv-key">{k}</span>
              <span className="kv-val">{v === '' ? <em style={{color:'#666'}}>vacío</em> : String(v)}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )

  // PMA: delete row
  if (label === 'pma_delete_row') return (
    <div className="body-detail">
      {body.table       && <p>📋 Tabla: <span className="highlight">{body.table}</span></p>}
      {body.row_index !== undefined && <p>🔢 Índice fila: <span className="highlight">{body.row_index}</span></p>}
      {body.deleted_row && Object.keys(body.deleted_row).length > 0 && (
        <>
          <p className="preview-label">Fila eliminada:</p>
          <div className="body-kv">
            {Object.entries(body.deleted_row).map(([k, v]) => (
              <div key={k} className="kv-row">
                <span className="kv-key">{k}</span>
                <span className="kv-val">{v === null ? <em style={{color:'#666'}}>NULL</em> : String(v)}</span>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  )

  // Fallback genérico: JSON legible
  return (
    <div className="body-detail">
      <pre className="body-json">{JSON.stringify(body, null, 2)}</pre>
    </div>
  )
}

export default function LogsViewer({ serviceId, serviceName, onClose, api, onRefresh }) {
  const [tab, setTab] = useState('normal')
  const [logs, setLogs] = useState([])
  const [loading, setLoading] = useState(true)

  const [filter, setFilter] = useState('')

  // Filtros HTTP
  const [typeFilter, setTypeFilter] = useState('')

  // Filtros MySQL
  const [queryTypeFilter, setQueryTypeFilter] = useState('')
  const [sqliFilter, setSqliFilter] = useState('all')
  const [toolFilter, setToolFilter] = useState('all')

  const serviceType = serviceId.split('-')[0]

  useEffect(() => {
    loadLogs()
  }, [serviceId, tab, typeFilter, queryTypeFilter, sqliFilter, toolFilter])

  const loadLogs = async () => {
    setLoading(true)
    try {
      if (tab === 'bruteforce') {
        const res = await api.get(`/api/logs?service_type=bruteforce&service_id=${serviceId}`)
        setLogs(res.data.logs || [])
      } else {
        let url = `/api/logs?service_id=${serviceId}`

        if (serviceType === 'mysql') {
          if (queryTypeFilter) url += `&query_type=${queryTypeFilter}`
          if (sqliFilter && sqliFilter !== 'all') url += `&sqli_pattern=${sqliFilter}`
          if (toolFilter && toolFilter !== 'all') url += `&detected_tool=${toolFilter}`
        } else if (serviceType === 'http') {
          if (typeFilter) url += `&request_type=${typeFilter}`
        }
        // SSH: solo service_id

        const res = await api.get(url)
        setLogs(res.data.logs || [])
      }
    } catch (err) {
      console.error('Error loading logs:', err)
    } finally {
      setLoading(false)
    }
  }

  const visibleLogs = filter
    ? logs.filter(log => JSON.stringify(log).toLowerCase().includes(filter.toLowerCase()))
    : logs

  const handleClearLogs = async () => {
    if (!window.confirm('¿Eliminar todos los logs de este servicio?')) return
    try {
      await api.delete(`/api/logs/cleanup/${serviceId}`)
      setLogs([])
      onRefresh()
    } catch (err) {
      alert(err.response?.data?.detail || 'Error al limpiar logs')
    }
  }

  // ── Colores y títulos ──

  const getLogColor = (log) => {
    if (log.total_attempts) return 'warning'
    if (log.query_type === 'login_attempt' || log.request_type === 'login_attempt') {
      return log.login_success === true ? 'success' : 'danger'
    }
    if (log.request_type === 'page_view') return 'info'
    if (log.commands?.length > 0) return 'danger'
    if (log.auth_attempts > 0) return 'warning'
    if (log.sqli_pattern && log.sqli_pattern !== 'none') return 'danger'
    if (['drop', 'delete', 'update'].includes(log.query_type)) return 'warning'
    // Acciones destructivas HTTP
    if (['wp_delete_post','wp_delete_user','pma_delete_row','pma_sql_drop'].includes(log.action_label)) return 'danger'
    if (['wp_create_user','pma_insert_row','pma_sql_insert'].includes(log.action_label)) return 'warning'
    if (log.action_label && log.action_label.startsWith('pma_sql_')) return 'warning'
    if (log.action_label) return 'default'
    return 'default'
  }

  const getLogTitle = (log) => {
    if (log.total_attempts !== undefined) {
      if (log.action?.includes('rate_limit')) return `🚫 Rate Limit — ${log.total_attempts} requests`
      return `🔓 Brute Force — ${log.total_attempts} intentos`
    }

    if (log.query_type === 'login_attempt') return log.login_success ? '✅ Login exitoso' : '❌ Login fallido'
    if (log.query_type === 'select')        return '🔍 MySQL SELECT'
    if (log.query_type === 'insert')        return '➕ MySQL INSERT'
    if (log.query_type === 'update')        return '✏️ MySQL UPDATE'
    if (log.query_type === 'delete')        return '🗑️ MySQL DELETE'
    if (log.query_type === 'drop')          return '💥 MySQL DROP'
    if (log.query_type === 'create')        return '🏗️ MySQL CREATE'
    if (log.query_type)                     return `🗄️ MySQL ${log.query_type.toUpperCase()}`

    if (log.request_type === 'login_attempt') return log.login_success ? '✅ Login exitoso' : '❌ Login fallido'
    if (log.request_type === 'page_view')     return '🌐 Page View'

    // Acciones WordPress con etiqueta semántica
    const wpLabels = {
      wp_save_post:    '📝 WP — Guardó post',
      wp_delete_post:  '🗑️ WP — Eliminó post',
      wp_create_user:  '👤 WP — Creó usuario',
      wp_delete_user:  '🗑️ WP — Eliminó usuario',
      wp_save_options: '⚙️ WP — Cambió settings',
      wp_xmlrpc_call:  '📡 WP — XML-RPC call',
    }
    // Acciones phpMyAdmin
    const pmaLabels = {
      pma_sql_select:  '🔍 PMA — SQL SELECT',
      pma_sql_insert:  '➕ PMA — SQL INSERT',
      pma_sql_update:  '✏️ PMA — SQL UPDATE',
      pma_sql_delete:  '🗑️ PMA — SQL DELETE',
      pma_sql_drop:    '💥 PMA — SQL DROP',
      pma_sql_create:  '🏗️ PMA — SQL CREATE',
      pma_sql_alter:   '🔧 PMA — SQL ALTER',
      pma_sql_show:    '📋 PMA — SQL SHOW',
      pma_sql_describe:'📋 PMA — SQL DESCRIBE',
      pma_sql_query:   '🗄️ PMA — SQL query',
      pma_insert_row:  '➕ PMA — Insertó fila',
      pma_delete_row:  '🗑️ PMA — Eliminó fila',
    }
    if (log.action_label && wpLabels[log.action_label])  return wpLabels[log.action_label]
    if (log.action_label && pmaLabels[log.action_label]) return pmaLabels[log.action_label]
    if (log.action_label) return `🔧 ${log.action_label}`

    if (log.request_type) return `🌐 ${log.request_type}`

    if (log.commands !== undefined) return `🔌 SSH Session`

    return 'Event'
  }

  const formatTimestamp = (log) => {
    const ts = log.timestamp || log.session_start || log.detected_at
    if (!ts) return 'N/A'
    return new Date(ts).toLocaleString()
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="logs-modal" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <h2>📋 Logs — {serviceName}</h2>
          <button className="close-btn" onClick={onClose}>✕</button>
        </div>

        <div className="logs-tabs">
          <button
            className={`tab-btn ${tab === 'normal' ? 'active' : ''}`}
            onClick={() => {
              setTab('normal')
              setTypeFilter('')
              setQueryTypeFilter('')
              setSqliFilter('all')
              setToolFilter('all')
            }}
          >
            📝 Logs Normales
          </button>
          <button
            className={`tab-btn ${tab === 'bruteforce' ? 'active' : ''}`}
            onClick={() => setTab('bruteforce')}
          >
            ⚠️ Brute Force
          </button>
        </div>

        <div className="logs-filters">
          <input
            type="text"
            placeholder="🔍 Buscar..."
            value={filter}
            onChange={e => setFilter(e.target.value)}
            className="search-input"
          />

          {tab === 'normal' && serviceType === 'http' && (
            <select
              value={typeFilter}
              onChange={e => setTypeFilter(e.target.value)}
              className="filter-select"
            >
              <option value="">Todos los tipos</option>
              <option value="page_view">Page View</option>
              <option value="login_attempt">Login Attempt</option>
              <option value="other_form">Other Form</option>
            </select>
          )}

          {tab === 'normal' && serviceType === 'mysql' && (
            <>
              <select
                value={queryTypeFilter}
                onChange={e => setQueryTypeFilter(e.target.value)}
                className="filter-select"
              >
                <option value="">Todos los tipos</option>
                {MYSQL_QUERY_TYPES.map(t => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </select>

              <select
                value={sqliFilter}
                onChange={e => setSqliFilter(e.target.value)}
                className="filter-select"
              >
                {SQLI_PATTERNS.map(({ value, label }) => (
                  <option key={value} value={value}>{label}</option>
                ))}
              </select>

              <select
                value={toolFilter}
                onChange={e => setToolFilter(e.target.value)}
                className="filter-select"
              >
                {TOOL_OPTIONS.map(({ value, label }) => (
                  <option key={value} value={value}>{label}</option>
                ))}
              </select>
            </>
          )}

          <button className="btn btn-danger btn-sm" onClick={handleClearLogs}>
            🗑 Limpiar
          </button>
        </div>

        <div className="logs-container">
          {loading ? (
            <p>Cargando...</p>
          ) : visibleLogs.length === 0 ? (
            <p className="no-logs">Sin logs</p>
          ) : (
            <div className="logs-list">
              {visibleLogs.map((log, idx) => (
                <div key={idx} className={`log-entry log-${getLogColor(log)}`}>
                  <div className="log-header">
                    <span className="log-timestamp">🕐 {formatTimestamp(log)}</span>
                    <span className="log-type">{getLogTitle(log)}</span>
                  </div>

                  <div className="log-content">
                    {log.ip && <p>👤 IP: <span className="highlight">{log.ip}</span></p>}

                    {log.request_type === 'login_attempt' && (
                      <>
                        {log.username && <p>👁️ Usuario: <span className="highlight">{log.username}</span></p>}
                        {log.password && <p>🔐 Contraseña: <span className="highlight">{log.password}</span></p>}
                        {log.login_success !== undefined && (
                          <p>✓ Resultado: <span className={log.login_success ? 'success' : 'danger'}>
                            {log.login_success ? '✓ Exitoso' : '✗ Fallido'}
                          </span></p>
                        )}
                        {log.path && <p>🔗 Path: <span className="highlight">{log.path}</span></p>}
                        {log.status_code && <p>📊 Status: <span className="highlight">{log.status_code}</span></p>}
                      </>
                    )}

                    {log.request_type === 'page_view' && (
                      <>
                        {log.path && <p>🔗 Path: <span className="highlight">{log.path}</span></p>}
                        {log.status_code && <p>📊 Status: <span className="highlight">{log.status_code}</span></p>}
                      </>
                    )}

                    {/* ── Bloque de acciones HTTP con body semántico ── */}
                    {log.action_label && log.body && (
                      <div className="action-body">
                        <p className="action-label-badge">
                          🔖 <span className="highlight">{log.action_label}</span>
                          {log.path && <span style={{color:'#8899aa', fontSize:'11px', marginLeft:'8px'}}>{log.path}</span>}
                        </p>
                        <ActionBody label={log.action_label} body={log.body} />
                      </div>
                    )}

                    {log.total_attempts && (
                      <>
                        <p>⚠️ Total intentos: <span className="highlight">{log.total_attempts}</span></p>
                        {log.action && <p>🚫 Acción: <span className="highlight">{log.action}</span></p>}
                        {log.credentials_tried && log.credentials_tried.length > 0 && (
                          <div className="credentials-table">
                            <p className="table-title">📋 Credenciales Intentadas:</p>
                            <table>
                              <thead>
                                <tr><th>#</th><th>Usuario</th><th>Contraseña</th></tr>
                              </thead>
                              <tbody>
                                {log.credentials_tried.map((cred, i) => (
                                  <tr key={i}>
                                    <td>{i+1}</td>
                                    <td className="highlight">{cred.username || 'N/A'}</td>
                                    <td className="highlight">
                                      {cred.invalid_user ? '🚫 Usuario inválido' : (cred.password || 'N/A')}
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        )}
                        {log.action?.includes('rate_limit') && (
                          <div className="rate-limit-info">
                            <p className="info-text">
                              🚫 Múltiples requests GET en corto tiempo desde <span className="highlight">{log.ip}</span>
                            </p>
                          </div>
                        )}
                      </>
                    )}

                    {log.commands !== undefined && (
                      <>
                        {log.username && <p>👁️ User: <span className="highlight">{log.username}</span></p>}
                        {log.password && <p>🔐 Pass: <span className="highlight">{log.password}</span></p>}
                        {log.auth_attempts > 0 && (
                          <p>🔑 Intentos auth: <span className="highlight">{log.auth_attempts}</span></p>
                        )}
                        {log.commands?.length > 0 && (
                          <div className="ssh-commands">
                            <p>💻 Comandos ejecutados:</p>
                            <div className="command-list">
                              {log.commands.map((cmd, i) => (
                                <div key={i} className="command-item">
                                  <span className="cmd-time">🕐 {new Date(cmd.timestamp).toLocaleString()}</span>
                                  <span className="cmd-text">$ {cmd.command}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </>
                    )}

                    {serviceType === 'mysql' && (() => {
                      const qt = log.query_type
                      return (
                        <>
                          {log.username && <p>👁️ Usuario: <span className="highlight">{log.username}</span></p>}
                          {log.database_name && log.database_name !== 'unknown' && (
                            <p>🗄️ Base de datos: <span className="highlight">{log.database_name}</span></p>
                          )}

                          {qt && !['login_attempt', 'connect'].includes(qt) && log.query && (
                            <p style={{wordBreak:'break-all'}}>
                              💻 Query: <span className="highlight">{log.query}</span>
                            </p>
                          )}

                          {log.sqli_pattern && log.sqli_pattern !== 'none' && (
                            <p>⚠️ Patrón SQLi: <span className="highlight">{log.sqli_pattern}</span></p>
                          )}
                          {log.detected_tool && log.detected_tool !== 'none' && (
                            <p>🛠️ Herramienta: <span className="highlight">{log.detected_tool}</span></p>
                          )}

                          {log.template_name && (
                            <p>📄 Plantilla: <span className="highlight">{log.template_name}</span></p>
                          )}
                        </>
                      )
                    })()}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}