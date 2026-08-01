import { useState, useEffect } from 'react'
import API from '../utils/api'
import '../styles/Modal.css'

const DEFAULT_SSH_USERS_TEXT = `admin:admin12345
ubuntu:ubuntu
deploy:deploy123
test:test1234
juan:juancho`

const DEFAULT_CONFIGS = {
  ssh: {
    ban_seconds: 600,
    failed_threshold: 20,
    users: DEFAULT_SSH_USERS_TEXT,
  },
  http: {
    template: 'wordpress',
    enable_rate_limit: true,
    rate_limit_threshold: 30,
    rate_limit_window: 15,
    ban_seconds: 600,
    failed_threshold: 20,
    valid_credentials: { username: 'admin', password: 'admin123' },
  },
  mysql: {
    template: 'empty',
    db_user: 'honeypot',
    db_password: 'password123',
    ban_seconds: 600,
    failed_threshold: 20,
  }
}

const validateUsersText = (text) => {
  const errors = []
  const lines = text.trim().split('\n').filter(l => l.trim())
  if (lines.length === 0) {
    errors.push('Debes definir al menos un usuario')
    return errors
  }
  lines.forEach((line, i) => {
    const parts = line.split(':')
    if (parts.length < 2) {
      errors.push(`Linea ${i + 1}: formato invalido "${line}" — esperado usuario:contrasena`)
      return
    }
    const username = parts[0].trim()
    const password = parts.slice(1).join(':').trim()
    if (!username) errors.push(`Linea ${i + 1}: el usuario no puede estar vacio`)
    if (!password) errors.push(`Linea ${i + 1}: la contrasena no puede estar vacia`)
    if (/\s/.test(username)) errors.push(`Linea ${i + 1}: el usuario no puede contener espacios`)
  })
  return errors
}

export default function EditConfigModal({ service, onClose, onSave }) {
  const [port, setPort] = useState(service.port)
  const [persistent, setPersistent] = useState(service.persistent ?? false)
  const [config, setConfig] = useState(service.config || DEFAULT_CONFIGS[service.type])
  const [templates, setTemplates] = useState([])
  const [loadingTemplates, setLoadingTemplates] = useState(false)
  const [saving, setSaving] = useState(false)
  const [sshUsersErrors, setSshUsersErrors] = useState([])
  const [error, setError] = useState('')
  const [uploadFile, setUploadFile] = useState(null)
  const [uploading, setUploading] = useState(false)

  // Estado local para el toggle de rate limiting
  const [enableRateLimit, setEnableRateLimit] = useState(
    config.enable_rate_limit !== false
  )

  // Asegurar que usersText sea siempre un string
  const usersText = typeof config.users === 'string' ? config.users : DEFAULT_SSH_USERS_TEXT

  useEffect(() => {
    if (service.type === 'mysql') {
      loadTemplates()
    }
  }, [])

  const loadTemplates = async () => {
    try {
      setLoadingTemplates(true)
      const res = await API.get('/api/templates')
      setTemplates(res.data.templates || [])
    } catch (err) {
      console.error('Error loading templates:', err)
      setError('Error loading templates')
    } finally {
      setLoadingTemplates(false)
    }
  }

  const handleUploadTemplate = async () => {
    if (!uploadFile) {
      setError('Please select a file')
      return
    }

    setUploading(true)
    try {
      const formData = new FormData()
      formData.append('file', uploadFile)

      await API.post('/api/templates/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      })

      setError('')
      setUploadFile(null)
      await loadTemplates()
      alert('Template uploaded successfully')
    } catch (err) {
      setError(err.response?.data?.detail || 'Error uploading template')
    } finally {
      setUploading(false)
    }
  }

  // Filtra el config para que solo contenga los campos válidos de cada tipo.
  // Necesario porque el backend usa extra='forbid' en los schemas Pydantic.
  const sanitizeConfig = (rawConfig) => {
    if (service.type === 'ssh') {
      return {
        ban_seconds: rawConfig.ban_seconds ?? 600,
        failed_threshold: rawConfig.failed_threshold ?? 20,
        users: rawConfig.users ?? DEFAULT_SSH_USERS_TEXT,
      }
    }
    if (service.type === 'http') {
      return {
        template: rawConfig.template ?? 'wordpress',
        enable_rate_limit: enableRateLimit,
        rate_limit_threshold: rawConfig.rate_limit_threshold ?? 30,
        rate_limit_window: rawConfig.rate_limit_window ?? 15,
        ban_seconds: rawConfig.ban_seconds ?? 600,
        failed_threshold: rawConfig.failed_threshold ?? 20,
        valid_credentials: rawConfig.valid_credentials ?? { username: 'admin', password: 'admin123' },
      }
    }
    if (service.type === 'mysql') {
      return {
        template: rawConfig.template ?? 'empty',
        db_user: rawConfig.db_user ?? 'honeypot',
        db_password: rawConfig.db_password ?? 'password123',
        ban_seconds: rawConfig.ban_seconds ?? 600,
        failed_threshold: rawConfig.failed_threshold ?? 20,
      }
    }
    return rawConfig
  }

  const handleSave = async () => {
    setError('')

    // Validar puerto
    if (port < 1024 || port > 65535) {
      setError('Port must be between 1024 and 65535')
      return
    }

    // Validar credenciales para HTTP
    if (service.type === 'http') {
      const creds = config.valid_credentials
      if (!creds || !creds.username || !creds.password) {
        setError('Valid Credentials (username and password) are required for HTTP services')
        return
      }
    }

    // Validar usuarios SSH antes de guardar
    if (service.type === 'ssh') {
      const usersText = typeof config.users === 'string' ? config.users : DEFAULT_SSH_USERS_TEXT
      const errs = validateUsersText(usersText)
      setSshUsersErrors(errs)
      if (errs.length > 0) return
    }

    setSaving(true)
    try {
      const cleanConfig = sanitizeConfig(config)
      await onSave({ port, persistent, config: cleanConfig })
    } catch (err) {
      setError(err.response?.data?.detail || 'Error saving configuration')
    } finally {
      setSaving(false)
    }
  }

  const handleDeleteTemplate = async (templateName) => {
    if (!window.confirm(`Delete template '${templateName}'?`)) return

    try {
      await API.delete(`/api/templates/${templateName}`)
      await loadTemplates()
      if (config.template === templateName) {
        setConfig({ ...config, template: 'empty' })
      }
    } catch (err) {
      setError(err.response?.data?.detail || 'Error deleting template')
    }
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <h2>⚙️ Configure {service.name}</h2>
          <button className="close-btn" onClick={onClose}>✕</button>
        </div>

        <div className="modal-body">
          {error && <div className="error">{error}</div>}

          <div className="form-group">
            <label>Port</label>
            <input
              type="number"
              value={port}
              onChange={e => setPort(parseInt(e.target.value))}
              min="1024"
              max="65535"
            />
            <small>📌 Use ports 1024-65535 and ensure it's not in use</small>
          </div>

          {/* Persistent toggle */}
          <div className="toggle-group">
            <div className="toggle-info">
              <span className="toggle-label">Persistent</span>
              <span className="toggle-description">
                {persistent
                  ? 'El contenedor se conserva al detenerlo (se pausa)'
                  : 'El contenedor se destruye al detenerlo'}
              </span>
            </div>
            <button
              className={`toggle-switch ${persistent ? 'toggle-switch--on' : ''}`}
              onClick={() => setPersistent(!persistent)}
              aria-label="Toggle persistent"
            >
              <span className="toggle-thumb" />
            </button>
          </div>

          {/* ========== MYSQL CONFIG ========== */}
          {service.type === 'mysql' && (
            <>
              <div className="form-group">
                <label>Database Template</label>
                {loadingTemplates ? (
                  <p>Loading templates...</p>
                ) : (
                  <select
                    value={config.template || 'empty'}
                    onChange={e => setConfig({ ...config, template: e.target.value })}
                  >
                    {templates.map(t => (
                      <option key={t.name} value={t.name}>
                        {t.name} ({t.type}) - {t.size_kb}KB
                      </option>
                    ))}
                  </select>
                )}
                <small>Selecciona la plantilla para tu base de datos</small>
              </div>

              {/* Mensaje informativo sobre el nombre de la base de datos */}
              <div className="modal-warning" style={{ margin: '0 0 16px 0' }}>
                <strong>ℹ️ Base de datos:</strong> El nombre de la base de datos se toma automáticamente del archivo <code>.sql</code> si incluye <code>CREATE DATABASE</code> o <code>USE</code>. 
                Si no lo incluye, se usará <code>honeypot</code>. Asegúrate de que tu plantilla defina la base de datos correctamente.
              </div>

              <div className="upload-section">
                <h4>Upload Custom Template</h4>
                <div className="upload-group">
                  <input
                    type="file"
                    accept=".sql"
                    onChange={e => setUploadFile(e.target.files?.[0])}
                    disabled={uploading}
                  />
                  <button
                    className="btn btn-secondary"
                    onClick={handleUploadTemplate}
                    disabled={!uploadFile || uploading}
                  >
                    {uploading ? 'Uploading...' : 'Upload Template'}
                  </button>
                </div>
                <small>Sube un archivo .sql con sentencias CREATE e INSERT</small>
              </div>

              <div className="form-group">
                <label>Database User</label>
                <input
                  type="text"
                  placeholder="Database user"
                  value={config.db_user || 'honeypot'}
                  onChange={e => setConfig({ ...config, db_user: e.target.value })}
                />
              </div>

              <div className="form-group">
                <label>Database Password</label>
                <input
                  type="password"
                  placeholder="Database password"
                  value={config.db_password || 'password123'}
                  onChange={e => setConfig({ ...config, db_password: e.target.value })}
                />
              </div>

              <div className="form-group">
                <label>Ban Duration (seconds)</label>
                <input
                  type="number"
                  value={config.ban_seconds || 600}
                  onChange={e => setConfig({ ...config, ban_seconds: parseInt(e.target.value) })}
                  min="1"
                />
                <small>Tiempo de bloqueo para IPs que superen el umbral</small>
              </div>

              <div className="form-group">
                <label>Failed Attempts Threshold</label>
                <input
                  type="number"
                  value={config.failed_threshold || 20}
                  onChange={e => setConfig({ ...config, failed_threshold: parseInt(e.target.value) })}
                  min="1"
                />
                <small>Número de intentos fallidos antes de bloquear la IP</small>
              </div>
            </>
          )}

          {/* ========== HTTP CONFIG ========== */}
          {service.type === 'http' && (
            <>
              <div className="form-group">
                <label>Template</label>
                <select
                  value={config.template || 'wordpress'}
                  onChange={e => setConfig({ ...config, template: e.target.value })}
                >
                  <option value="wordpress">WordPress</option>
                  <option value="xampp">XAMPP</option>
                </select>
              </div>

              {/* Credenciales válidas */}
              <div className="form-group">
                <label>
                  Valid Credentials <span className="required-mark">*</span>
                </label>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <input
                    type="text"
                    placeholder="Username"
                    value={config.valid_credentials?.username || ''}
                    onChange={e => setConfig({
                      ...config,
                      valid_credentials: {
                        ...config.valid_credentials,
                        username: e.target.value
                      }
                    })}
                    style={{ flex: 1 }}
                    required
                  />
                  <input
                    type="text"
                    placeholder="Password"
                    value={config.valid_credentials?.password || ''}
                    onChange={e => setConfig({
                      ...config,
                      valid_credentials: {
                        ...config.valid_credentials,
                        password: e.target.value
                      }
                    })}
                    style={{ flex: 1 }}
                    required
                  />
                </div>
                <small>Credenciales que se consideran válidas en el formulario de login</small>
              </div>

              {/* Rate Limiting toggle */}
              <div className="toggle-group">
                <div className="toggle-info">
                  <span className="toggle-label">Enable Rate Limiting</span>
                  <span className="toggle-description">
                    {enableRateLimit ? 'Activo' : 'Inactivo'}
                  </span>
                </div>
                <button
                  className={`toggle-switch ${enableRateLimit ? 'toggle-switch--on' : ''}`}
                  onClick={() => {
                    const newVal = !enableRateLimit
                    setEnableRateLimit(newVal)
                    setConfig({ ...config, enable_rate_limit: newVal })
                  }}
                  aria-label="Toggle rate limiting"
                >
                  <span className="toggle-thumb" />
                </button>
              </div>

              {enableRateLimit && (
                <>
                  <div className="form-group">
                    <label>Rate Limit Threshold (GETs)</label>
                    <input
                      type="number"
                      value={config.rate_limit_threshold || 30}
                      onChange={e => setConfig({ ...config, rate_limit_threshold: parseInt(e.target.value) })}
                      min="1"
                    />
                  </div>

                  <div className="form-group">
                    <label>Rate Limit Window (seconds)</label>
                    <input
                      type="number"
                      value={config.rate_limit_window || 15}
                      onChange={e => setConfig({ ...config, rate_limit_window: parseInt(e.target.value) })}
                      min="1"
                    />
                  </div>
                </>
              )}

              <div className="form-group">
                <label>Ban Duration (seconds)</label>
                <input
                  type="number"
                  value={config.ban_seconds || 600}
                  onChange={e => setConfig({ ...config, ban_seconds: parseInt(e.target.value) })}
                  min="1"
                />
              </div>

              <div className="form-group">
                <label>Failed Attempts Threshold</label>
                <input
                  type="number"
                  value={config.failed_threshold || 20}
                  onChange={e => setConfig({ ...config, failed_threshold: parseInt(e.target.value) })}
                  min="1"
                />
              </div>
            </>
          )}

          {/* ========== SSH CONFIG ========== */}
          {service.type === 'ssh' && (
            <>
              <div className="form-group">
                <label>Ban Duration (seconds)</label>
                <input
                  type="number"
                  value={config.ban_seconds || 600}
                  onChange={e => setConfig({ ...config, ban_seconds: parseInt(e.target.value) })}
                  min="1"
                />
              </div>

              <div className="form-group">
                <label>Failed Attempts Threshold</label>
                <input
                  type="number"
                  value={config.failed_threshold || 20}
                  onChange={e => setConfig({ ...config, failed_threshold: parseInt(e.target.value) })}
                  min="1"
                />
              </div>

              <div className="form-group">
                <label>Honeypot Users</label>
                <small>Un usuario por línea: <code>usuario:contraseña</code></small>
                <textarea
                  rows={8}
                  className="config-textarea"
                  value={usersText}
                  onChange={e => {
                    const val = e.target.value
                    setConfig({ ...config, users: val })
                    setSshUsersErrors(validateUsersText(val))
                  }}
                  placeholder={"admin:admin123\nubuntu:ubuntu\ndeploy:deploy123"}
                  spellCheck={false}
                />
                {sshUsersErrors.length > 0 && (
                  <div style={{ marginTop: '6px' }}>
                    {sshUsersErrors.map((err, i) => (
                      <p key={i} className="config-validation-error">⚠ {err}</p>
                    ))}
                  </div>
                )}
                {sshUsersErrors.length === 0 && usersText.trim() && (
                  <p className="config-validation-success">
                    ✓ {usersText.trim().split('\n').filter(l => l.trim()).length} usuario(s) válido(s)
                  </p>
                )}
              </div>
            </>
          )}
        </div>

        <div className="modal-footer">
          <button className="btn btn-secondary" onClick={onClose} disabled={saving || uploading}>
            Cancel
          </button>
          <button className="btn btn-primary" onClick={handleSave} disabled={saving || uploading}>
            {saving ? 'Saving...' : 'Save & Restart'}
          </button>
        </div>
      </div>
    </div>
  )
}