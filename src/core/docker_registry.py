"""Docker registry client for fetching image information."""

import requests
from typing import List, Optional, Dict, Any, Tuple
from dataclasses import dataclass
import base64
import json
import logging
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)


@dataclass
class ImageTag:
    """Represents a Docker image tag."""
    name: str
    pushed_at: Optional[str] = None
    digest: Optional[str] = None
    architecture: Optional[str] = None


@dataclass
class RegistryConfig:
    """Registry configuration for authentication."""
    registry_url: str
    username: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None


class DockerRegistryClient:
    """Client for interacting with Docker registries."""

    def __init__(self, timeout: int = 30):
        """Initialize the registry client.

        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'evergreen-python/1.0.0',
            'Accept': 'application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json'
        })

    def get_available_tags(self, image_name: str, registry_config: RegistryConfig,
                          max_tags: int = 100) -> List[ImageTag]:
        """Get available tags for a Docker image.

        Args:
            image_name: Name of the Docker image
            registry_config: Registry configuration
            max_tags: Maximum number of tags to retrieve

        Returns:
            List of available image tags

        Raises:
            requests.RequestException: If registry request fails
        """
        # Normalize image name for registry API
        normalized_name = self._normalize_image_name(image_name, registry_config.registry_url)

        # Get authentication headers
        auth_headers = self._get_auth_headers(normalized_name, registry_config)
        if auth_headers is None:
            raise requests.RequestException(f"Authentication failed for {registry_config.registry_url}")

        # Build tags URL
        if self._is_docker_hub(registry_config.registry_url):
            return self._get_docker_hub_tags(normalized_name, max_tags)
        else:
            return self._get_registry_v2_tags(normalized_name, registry_config, auth_headers, max_tags)

    def get_image_digest(self, image_name: str, tag: str, registry_config: RegistryConfig) -> Optional[str]:
        """Get the digest for a specific image tag.

        Args:
            image_name: Name of the Docker image
            tag: Tag to get digest for
            registry_config: Registry configuration

        Returns:
            Image digest or None if not found
        """
        normalized_name = self._normalize_image_name(image_name, registry_config.registry_url)

        # Get authentication headers
        auth_headers = self._get_auth_headers(normalized_name, registry_config)
        if auth_headers is None:
            return None

        # Build manifest URL
        manifest_url = self._build_manifest_url(normalized_name, tag, registry_config.registry_url)

        try:
            headers = dict(auth_headers)
            headers['Accept'] = 'application/vnd.docker.distribution.manifest.v2+json'

            response = self.session.head(manifest_url, headers=headers, timeout=self.timeout)
            response.raise_for_status()

            return response.headers.get('Docker-Content-Digest')

        except requests.RequestException as e:
            logger.warning(f"Failed to get digest for {image_name}:{tag}: {e}")
            return None

    def _normalize_image_name(self, image_name: str, registry_url: str) -> str:
        """Normalize image name for registry API.

        Args:
            image_name: Original image name
            registry_url: Registry URL

        Returns:
            Normalized image name
        """
        # Handle Docker Hub library images
        if self._is_docker_hub(registry_url) and '/' not in image_name:
            return f"library/{image_name}"

        return image_name

    def _is_docker_hub(self, registry_url: str) -> bool:
        """Check if registry is Docker Hub.

        Args:
            registry_url: Registry URL

        Returns:
            True if Docker Hub
        """
        return "docker.io" in registry_url or "index.docker.io" in registry_url

    def _get_auth_headers(self, image_name: str, registry_config: RegistryConfig) -> Optional[Dict[str, str]]:
        """Get authentication headers for registry.

        Args:
            image_name: Image name
            registry_config: Registry configuration

        Returns:
            Authentication headers or None if auth failed
        """
        # Try to access registry without authentication first
        auth_check_url = self._build_auth_check_url(image_name, registry_config.registry_url)

        try:
            response = self.session.get(auth_check_url, timeout=self.timeout)

            if response.status_code == 200:
                # No authentication required
                return {}

            if response.status_code != 401:
                logger.warning(f"Unexpected response from registry: {response.status_code}")
                return None

            # Parse WWW-Authenticate header
            auth_header = response.headers.get('WWW-Authenticate', '')
            if not auth_header:
                return None

            return self._handle_authentication(auth_header, image_name, registry_config)

        except requests.RequestException as e:
            logger.error(f"Failed to check authentication for {registry_config.registry_url}: {e}")
            return None

    def _handle_authentication(self, auth_header: str, image_name: str,
                             registry_config: RegistryConfig) -> Optional[Dict[str, str]]:
        """Handle registry authentication.

        Args:
            auth_header: WWW-Authenticate header value
            image_name: Image name
            registry_config: Registry configuration

        Returns:
            Authentication headers or None if failed
        """
        if auth_header.startswith('Bearer'):
            return self._handle_bearer_auth(auth_header, image_name, registry_config)
        elif auth_header.startswith('Basic'):
            return self._handle_basic_auth(registry_config)
        else:
            logger.warning(f"Unsupported authentication method: {auth_header}")
            return None

    def _handle_bearer_auth(self, auth_header: str, image_name: str,
                           registry_config: RegistryConfig) -> Optional[Dict[str, str]]:
        """Handle Bearer token authentication.

        Args:
            auth_header: WWW-Authenticate header value
            image_name: Image name
            registry_config: Registry configuration

        Returns:
            Authentication headers with Bearer token
        """
        # Parse auth header to extract realm, service, and scope
        auth_params = {}
        parts = auth_header.replace('Bearer ', '').split(',')

        for part in parts:
            if '=' in part:
                key, value = part.split('=', 1)
                auth_params[key.strip()] = value.strip().strip('"')

        realm = auth_params.get('realm')
        service = auth_params.get('service')
        scope = auth_params.get('scope', f'repository:{image_name}:pull')

        if not realm:
            logger.error("No realm found in Bearer auth header")
            return None

        # Build token request
        token_url = realm
        params = {'service': service, 'scope': scope}

        # Add credentials if available
        auth = None
        if registry_config.username and registry_config.password:
            auth = (registry_config.username, registry_config.password)

        try:
            response = self.session.get(
                token_url,
                params=params,
                auth=auth,
                timeout=self.timeout
            )
            response.raise_for_status()

            token_data = response.json()
            token = token_data.get('token') or token_data.get('access_token')

            if token:
                return {'Authorization': f'Bearer {token}'}

        except requests.RequestException as e:
            logger.error(f"Failed to get Bearer token: {e}")

        return None

    def _handle_basic_auth(self, registry_config: RegistryConfig) -> Optional[Dict[str, str]]:
        """Handle Basic authentication.

        Args:
            registry_config: Registry configuration

        Returns:
            Authentication headers with Basic auth
        """
        if not (registry_config.username and registry_config.password):
            logger.error("Basic auth requires username and password")
            return None

        credentials = f"{registry_config.username}:{registry_config.password}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()

        return {'Authorization': f'Basic {encoded_credentials}'}

    def _get_docker_hub_tags(self, image_name: str, max_tags: int) -> List[ImageTag]:
        """Get tags from Docker Hub API.

        Args:
            image_name: Normalized image name
            max_tags: Maximum number of tags

        Returns:
            List of image tags
        """
        tags = []
        url = f"https://hub.docker.com/v2/repositories/{image_name}/tags/"

        try:
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()

            data = response.json()
            results = data.get('results', [])

            for tag_data in results[:max_tags]:
                tag = ImageTag(
                    name=tag_data.get('name', ''),
                    pushed_at=tag_data.get('tag_last_pushed'),
                    digest=tag_data.get('digest')
                )
                tags.append(tag)

        except requests.RequestException as e:
            logger.error(f"Failed to get Docker Hub tags for {image_name}: {e}")

        return tags

    def _get_registry_v2_tags(self, image_name: str, registry_config: RegistryConfig,
                             auth_headers: Dict[str, str], max_tags: int) -> List[ImageTag]:
        """Get tags using Docker Registry v2 API.

        Args:
            image_name: Normalized image name
            registry_config: Registry configuration
            auth_headers: Authentication headers
            max_tags: Maximum number of tags

        Returns:
            List of image tags
        """
        tags = []
        tags_url = self._build_tags_url(image_name, registry_config.registry_url)

        try:
            response = self.session.get(
                tags_url,
                headers=auth_headers,
                timeout=self.timeout
            )
            response.raise_for_status()

            data = response.json()
            tag_names = data.get('tags', [])

            # Limit number of tags
            for tag_name in tag_names[:max_tags]:
                tag = ImageTag(name=tag_name)
                tags.append(tag)

        except requests.RequestException as e:
            logger.error(f"Failed to get tags for {image_name}: {e}")

        return tags

    def _build_auth_check_url(self, image_name: str, registry_url: str) -> str:
        """Build URL for authentication check.

        Args:
            image_name: Image name
            registry_url: Registry URL

        Returns:
            Authentication check URL
        """
        base_url = registry_url.rstrip('/')
        if not base_url.endswith('/v2'):
            base_url = urljoin(base_url, '/v2/')

        return urljoin(base_url, f'{image_name}/tags/list')

    def _build_tags_url(self, image_name: str, registry_url: str) -> str:
        """Build URL for tags endpoint.

        Args:
            image_name: Image name
            registry_url: Registry URL

        Returns:
            Tags URL
        """
        base_url = registry_url.rstrip('/')
        if not base_url.endswith('/v2'):
            base_url = urljoin(base_url, '/v2/')

        return urljoin(base_url, f'{image_name}/tags/list')

    def _build_manifest_url(self, image_name: str, tag: str, registry_url: str) -> str:
        """Build URL for manifest endpoint.

        Args:
            image_name: Image name
            tag: Image tag
            registry_url: Registry URL

        Returns:
            Manifest URL
        """
        base_url = registry_url.rstrip('/')
        if not base_url.endswith('/v2'):
            base_url = urljoin(base_url, '/v2/')

        return urljoin(base_url, f'{image_name}/manifests/{tag}')


def create_registry_config(registry_url: str, username: Optional[str] = None,
                          password: Optional[str] = None, token: Optional[str] = None) -> RegistryConfig:
    """Create a registry configuration.

    Args:
        registry_url: Registry URL
        username: Username for authentication
        password: Password for authentication
        token: Token for authentication

    Returns:
        Registry configuration
    """
    return RegistryConfig(
        registry_url=registry_url,
        username=username,
        password=password,
        token=token
    )