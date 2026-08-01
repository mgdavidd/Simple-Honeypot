import os
import docker
from docker.errors import NotFound

class NetworkManager:
    def __init__(self, client: docker.DockerClient):
        self.client = client
        self.network_name = self._get_network_name()

    def _get_network_name(self) -> str:
        """
        Obtiene el nombre de la red a la que está conectado el contenedor actual.
        Si no se puede determinar, usa 'honeypot-net' como fallback.
        """
        container_id = os.getenv('HOSTNAME')  # En Docker, HOSTNAME es el ID corto
        if not container_id:
            return 'honeypot-net'

        try:
            container = self.client.containers.get(container_id)
            networks = container.attrs['NetworkSettings']['Networks']
            # Tomar la primera red que no sea 'bridge' ni 'none'
            for net_name in networks.keys():
                if net_name not in ('bridge', 'none'):
                    print(f"[network] Usando red detectada: {net_name}")
                    return net_name
        except Exception as e:
            print(f"[network] Error al detectar red: {e}")

        # Fallback
        return 'honeypot-net'

    def ensure_network(self):
        try:
            self.client.networks.get(self.network_name)
        except NotFound:
            self.client.networks.create(
                name=self.network_name,
                driver="bridge",
                attachable=True,
            )
            print(f"[network] Red creada: {self.network_name}")

    def get_network_name(self) -> str:
        return self.network_name

    def get_network(self):
        try:
            return self.client.networks.get(self.network_name)
        except NotFound:
            self.ensure_network()
            return self.client.networks.get(self.network_name)