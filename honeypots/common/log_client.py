import os
import requests
import json
import time
from typing import Dict, Any
from .time_utils import colombia_now

API_URL = os.getenv("API_URL", "http://api:8000")

RETRY_ATTEMPTS = 3
RETRY_DELAY = 1  # segundos


def send_log(service_id: str, data: Dict[str, Any], retry: int = RETRY_ATTEMPTS):
    """
    Enviar un log a la API central.
    
    Args:
        service_id: El identificador del servicio (ej: "ssh-1", "ssh-2")
        data: Diccionario con los datos del evento
        retry: Número de reintentos en caso de fallo
    
    Example:
        send_log(
            service_id="ssh-1",
            data={
                "ip": "192.168.1.100",
                "username": "admin",
                "password": "password123",
                "auth_attempts": 1
            }
        )
    """
    
    if not service_id:
        print("[log_client] ERROR: service_id es requerido")
        return False
    
    if not API_URL:
        print("[log_client] WARNING: API_URL no está definido, no se puede enviar logs")
        return False
    
    # Asegurar que el timestamp esté presente si no existe
    if "timestamp" not in data and "connection_time" not in data and "detected_at" not in data:
        data["timestamp"] = colombia_now().isoformat()
    
    payload = {
        "service_id": service_id,
        "data": data
    }
    
    for attempt in range(retry):
        try:
            response = requests.post(
                f"{API_URL}/api/logs",
                json=payload,
                timeout=5
            )
            
            if response.status_code in [200, 201, 204]:
                print(f"[log_client] ✓ Log de {service_id} enviado exitosamente")
                return True
            else:
                print(f"[log_client] ✗ Error enviando log de {service_id}: {response.status_code}")
                print(f"[log_client] Respuesta: {response.text}")
                if attempt < retry - 1:
                    print(f"[log_client] Reintentando ({attempt + 1}/{retry})...")
                    time.sleep(RETRY_DELAY)
                continue
                
        except requests.exceptions.Timeout:
            print(f"[log_client] ✗ Timeout enviando log de {service_id} a {API_URL}")
            if attempt < retry - 1:
                print(f"[log_client] Reintentando ({attempt + 1}/{retry})...")
                time.sleep(RETRY_DELAY)
            continue
        except requests.exceptions.ConnectionError:
            print(f"[log_client] ✗ No se puede conectar a la API en {API_URL}")
            if attempt < retry - 1:
                print(f"[log_client] Reintentando ({attempt + 1}/{retry})...")
                time.sleep(RETRY_DELAY)
            continue
        except Exception as e:
            print(f"[log_client] ✗ Error enviando log de {service_id}: {type(e).__name__}: {e}")
            if attempt < retry - 1:
                print(f"[log_client] Reintentando ({attempt + 1}/{retry})...")
                time.sleep(RETRY_DELAY)
            continue
    
    print(f"[log_client] ✗ Falló después de {retry} intentos")
    return False


def send_ssh_log(service_id: str, ip: str, username: str = None, password: str = None, 
                 auth_attempts: int = 0, credentials_tried: list = None, commands: list = None,
                 port: int = None, connection_time: str = None):
    """Helper para enviar logs SSH específicos."""
    data = {
        "ip": ip,
        "username": username,
        "password": password,
        "auth_attempts": auth_attempts,
        "credentials_tried": credentials_tried or [],
        "commands": commands or [],
    }
    if port:
        data["port"] = port
    if connection_time:
        data["connection_time"] = connection_time
    
    return send_log(service_id=service_id, data=data)


def send_http_log(service_id: str, ip: str, method: str, path: str, 
                  user_agent: str = "", status_code: int = None, 
                  response_size: int = None, body: str = None):
    """Helper para enviar logs HTTP específicos."""
    data = {
        "ip": ip,
        "method": method,
        "path": path,
        "user_agent": user_agent,
    }
    if status_code is not None:
        data["status_code"] = status_code
    if response_size is not None:
        data["response_size"] = response_size
    if body is not None:
        data["body"] = body
    
    return send_log(service_id=service_id, data=data)

def send_http_login_attempt(service_id: str, ip: str, username: str, password: str = None,
                            success: bool = False, user_agent: str = "", 
                            path: str = "/", referer: str = None):
    """Helper específico para intentos de login HTTP."""
    data = {
        "ip": ip,
        "username": username,
        "success": success,
        "user_agent": user_agent,
        "path": path,
    }
    if password is not None:
        data["password"] = password
    if referer is not None:
        data["referer"] = referer
    
    return send_log(service_id=service_id, data=data)


def send_mysql_log(service_id: str, ip: str, username: str, query: str):
    """Helper para enviar logs MySQL específicos."""
    return send_log(
        service_id=service_id,
        data={
            "ip": ip,
            "username": username,
            "query": query
        }
    )


def send_bruteforce_alert(service_id: str, ip: str, total_attempts: int, 
                          credentials_tried: list, action: str = None, 
                          detected_at: str = None):
    """Helper para enviar alertas de fuerza bruta."""
    data = {
        "ip": ip,
        "total_attempts": total_attempts,
        "credentials_tried": credentials_tried,
    }
    if action:
        data["action"] = action
    if detected_at:
        data["detected_at"] = detected_at
    
    return send_log(service_id=service_id, data=data)