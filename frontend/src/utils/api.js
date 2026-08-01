import axios from 'axios'

const API = axios.create({
  baseURL: 'http://localhost:8000',
})

// Interceptor para manejar errores globalmente
API.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token')
      window.location.href = '/'
    }
    return Promise.reject(error)
  }
)

API.defaults.withCredentials = true;

export default API