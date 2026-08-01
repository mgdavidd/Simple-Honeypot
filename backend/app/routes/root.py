from fastapi import APIRouter

router = APIRouter()


@router.get("/")
def root():
    return {
        "name": "Honeypot Manager API",
        "version": "1.0.0",
        "status": "operational",
        "endpoints": {
            "Services": {
                "POST /api/services": "Crear servicio (ssh, http, mysql)",
                "GET /api/services": "Listar servicios activos",
                "GET /api/services/{id}": "Info de un servicio",
                "PATCH /api/services/{id}/stop": "Pausar/detener servicio",
                "PATCH /api/services/{id}/start": "Reanudar servicio (persistent=true)",
                "DELETE /api/services/{id}": "Destruir servicio"
            },
            "Logs": {
                "GET /api/logs": "Ver todos los logs o resumen",
                "GET /api/logs?service_type=ssh": "Logs SSH",
                "GET /api/logs?service_type=http": "Logs HTTP",
                "GET /api/logs?service_type=http&request_type=login_attempt": "Solo intentos de login",
                "GET /api/logs?service_type=bruteforce": "Alertas de fuerza bruta",
                "DELETE /api/logs/cleanup": "Eliminar todos los logs",
                "DELETE /api/logs/cleanup/{service_id}": "Eliminar logs de un servicio"
            }
        },
        "examples": {
            "Crear SSH": "POST /api/services {'type':'ssh','replica_id':1,'port':2222, 'persistent': true,'config':{'ban_seconds':600,'failed_threshold':20}}",
            "Crear HTTP WordPress": "POST /api/services {'type':'http','replica_id':1,'port':8080,'persistent': false,'config':{'template':'wordpress','valid_credentials':{'username':'admin','password':'admin123'}}}",
            "Crear HTTP XAMPP": "POST /api/services {'type':'http','replica_id':2,'port':8081,'config':{'template':'xampp','enable_rate_limit':false}}",
            "Ver logs SSH": "GET /api/logs?service_type=ssh",
            "Ver alertas brute force": "GET /api/logs?service_type=bruteforce",
            "Pausar servicio": "PATCH /api/services/ssh-1/stop",
            "Reanudar servicio": "PATCH /api/services/ssh-1/start",
            "Destruir servicio": "DELETE /api/services/ssh-1"
        },
        "posibles parametros para config": {
        "template": "wordpress (solo contenedor http)",
        "enable_rate_limit": "true (proteccion solo para peticiones GET a http)",
        "rate_limit_threshold": "30 (proteccion solo para peticiones GET a http)",
        "rate_limit_window": "15 (proteccion solo para peticiones GET a http)",
        "ban_seconds": "30 (para todos los servicios ssh, http, mysql al fallar login)",
        "failed_threshold": "10 (para todos los servicios al fallar login)",
        "valid_credentials": '{"username":"juan","password":"pass"} (todos los servicios)'
        }
    }