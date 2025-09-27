"""Configuration manager for evergreen-python."""

import json
import os
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class HostRule:
    """Host rule configuration for registry authentication."""
    host_type: str
    match_host: str
    username: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None


@dataclass
class Config:
    """Main configuration class."""
    enabled_managers: List[str]
    access_token: str
    gitlab_url: str
    repositories: List[str]
    schedule: Optional[str] = None
    automerge: bool = False
    create_mrs: bool = True
    labels: List[str] = None
    assignees: List[str] = None
    registry_urls: List[str] = None
    host_rules: List[HostRule] = None

    def __post_init__(self):
        """Initialize default values."""
        if self.labels is None:
            self.labels = []
        if self.assignees is None:
            self.assignees = []
        if self.registry_urls is None:
            self.registry_urls = ["https://index.docker.io"]
        if self.host_rules is None:
            self.host_rules = []


class ConfigManager:
    """Manages configuration loading and validation."""

    def __init__(self, config_path: str = "config/renovate.json"):
        """Initialize configuration manager.

        Args:
            config_path: Path to configuration file
        """
        self.config_path = config_path
        self._config: Optional[Config] = None

    def load_config(self) -> Config:
        """Load configuration from file.

        Returns:
            Loaded configuration

        Raises:
            FileNotFoundError: If config file doesn't exist
            ValueError: If config is invalid
        """
        if not os.path.exists(self.config_path):
            raise FileNotFoundError(f"Configuration file not found: {self.config_path}")

        try:
            with open(self.config_path, 'r') as f:
                config_data = json.load(f)

            self._config = self._parse_config(config_data)
            self._validate_config(self._config)

            logger.info(f"Configuration loaded from {self.config_path}")
            return self._config

        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in config file: {e}")
        except Exception as e:
            raise ValueError(f"Error loading configuration: {e}")

    def _parse_config(self, config_data: Dict[str, Any]) -> Config:
        """Parse configuration data into Config object.

        Args:
            config_data: Raw configuration dictionary

        Returns:
            Parsed configuration
        """
        # Parse host rules
        host_rules = []
        for rule_data in config_data.get("hostRules", []):
            host_rule = HostRule(
                host_type=rule_data.get("hostType", ""),
                match_host=rule_data.get("matchHost", ""),
                username=rule_data.get("username"),
                password=rule_data.get("password"),
                token=rule_data.get("token")
            )
            host_rules.append(host_rule)

        return Config(
            enabled_managers=config_data.get("enabledManagers", []),
            access_token=config_data.get("access_token", ""),
            gitlab_url=config_data.get("gitlab_url", ""),
            repositories=config_data.get("repositories", []),
            schedule=config_data.get("schedule"),
            automerge=config_data.get("automerge", False),
            create_mrs=config_data.get("createMRs", True),
            labels=config_data.get("labels", []),
            assignees=config_data.get("assignees", []),
            registry_urls=config_data.get("registryUrls", ["https://index.docker.io"]),
            host_rules=host_rules
        )

    def _validate_config(self, config: Config) -> None:
        """Validate configuration.

        Args:
            config: Configuration to validate

        Raises:
            ValueError: If configuration is invalid
        """
        if not config.enabled_managers:
            raise ValueError("enabledManagers cannot be empty")

        if "docker" not in config.enabled_managers:
            raise ValueError("Only 'docker' manager is supported")

        if not config.access_token:
            raise ValueError("access_token is required")

        if not config.gitlab_url:
            raise ValueError("gitlab_url is required")

        if not config.repositories:
            raise ValueError("repositories list cannot be empty")

        # Validate GitLab URL format
        if not config.gitlab_url.startswith(("http://", "https://")):
            raise ValueError("gitlab_url must start with http:// or https://")

        # Validate repository format (should be group/project)
        for repo in config.repositories:
            if "/" not in repo:
                logger.warning(f"Repository '{repo}' should be in 'group/project' format")

    @property
    def config(self) -> Config:
        """Get loaded configuration.

        Returns:
            Configuration object

        Raises:
            RuntimeError: If configuration not loaded
        """
        if self._config is None:
            raise RuntimeError("Configuration not loaded. Call load_config() first.")
        return self._config

    def get_host_rule(self, host: str) -> Optional[HostRule]:
        """Get host rule for a specific host.

        Args:
            host: Hostname to find rule for

        Returns:
            Matching host rule or None
        """
        if self._config is None:
            return None

        for rule in self._config.host_rules:
            if rule.match_host == host or host.endswith(rule.match_host):
                return rule

        return None

    def is_docker_enabled(self) -> bool:
        """Check if Docker manager is enabled.

        Returns:
            True if Docker manager is enabled
        """
        return self._config is not None and "docker" in self._config.enabled_managers


def load_config_from_env() -> Config:
    """Load configuration from environment variables.

    Returns:
        Configuration loaded from environment

    Raises:
        ValueError: If required environment variables are missing
    """
    access_token = os.getenv("GITLAB_ACCESS_TOKEN")
    gitlab_url = os.getenv("GITLAB_URL")
    repositories = os.getenv("REPOSITORIES", "").split(",")

    if not access_token:
        raise ValueError("GITLAB_ACCESS_TOKEN environment variable is required")

    if not gitlab_url:
        raise ValueError("GITLAB_URL environment variable is required")

    if not repositories or repositories == [""]:
        raise ValueError("REPOSITORIES environment variable is required (comma-separated)")

    return Config(
        enabled_managers=["docker"],
        access_token=access_token,
        gitlab_url=gitlab_url,
        repositories=[repo.strip() for repo in repositories if repo.strip()],
        schedule=os.getenv("SCHEDULE"),
        automerge=os.getenv("AUTOMERGE", "false").lower() == "true",
        create_mrs=os.getenv("CREATE_MRS", "true").lower() == "true",
        labels=os.getenv("LABELS", "dependencies,docker").split(","),
        assignees=os.getenv("ASSIGNEES", "").split(",") if os.getenv("ASSIGNEES") else [],
        registry_urls=os.getenv("REGISTRY_URLS", "https://index.docker.io").split(",")
    )