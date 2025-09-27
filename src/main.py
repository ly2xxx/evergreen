"""Main entry point for evergreen-python."""

import os
import sys
import time
import click
from typing import List, Dict, Any
import logging

# Add src to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.config_manager import ConfigManager, load_config_from_env
from core.dockerfile_parser import DockerfileParser, DockerDependency
from core.docker_registry import DockerRegistryClient, create_registry_config
from core.version_manager import DockerVersionManager, VersionUpdate
from platforms.gitlab_client import GitLabClient, FileChange
from utils.logging import setup_logging, get_log_level_from_env
from utils.cache import get_cache

logger = logging.getLogger(__name__)


class EvergreenPython:
    """Main evergreen-python application."""

    def __init__(self, config_path: str = None):
        """Initialize application.

        Args:
            config_path: Path to configuration file
        """
        # Setup logging
        log_level = get_log_level_from_env()
        setup_logging(level=log_level)

        # Load configuration
        if config_path:
            self.config_manager = ConfigManager(config_path)
            self.config = self.config_manager.load_config()
        else:
            # Try loading from environment
            try:
                self.config = load_config_from_env()
            except ValueError as e:
                logger.error(f"Failed to load configuration: {e}")
                sys.exit(1)

        # Initialize clients
        self.gitlab_client = GitLabClient(self.config.gitlab_url, self.config.access_token)
        self.dockerfile_parser = DockerfileParser()
        self.docker_client = DockerRegistryClient()
        self.version_manager = DockerVersionManager()
        self.cache = get_cache()

        logger.info("Evergreen-python initialized successfully")

    def run_scan(self, repositories: List[str] = None) -> Dict[str, Any]:
        """Run dependency scan on repositories.

        Args:
            repositories: List of repositories to scan (use config if None)

        Returns:
            Scan results summary
        """
        if repositories is None:
            repositories = self.config.repositories

        results = {
            'total_repositories': len(repositories),
            'successful_scans': 0,
            'failed_scans': 0,
            'total_updates': 0,
            'merge_requests_created': 0,
            'details': {}
        }

        logger.info(f"Starting scan of {len(repositories)} repositories")

        for repo in repositories:
            try:
                logger.info(f"Scanning repository: {repo}")
                repo_result = self._scan_repository(repo)
                results['details'][repo] = repo_result

                if repo_result['success']:
                    results['successful_scans'] += 1
                    results['total_updates'] += repo_result['updates_found']
                    results['merge_requests_created'] += repo_result['merge_requests_created']
                else:
                    results['failed_scans'] += 1

            except Exception as e:
                logger.error(f"Failed to scan repository {repo}: {e}")
                results['failed_scans'] += 1
                results['details'][repo] = {
                    'success': False,
                    'error': str(e),
                    'updates_found': 0,
                    'merge_requests_created': 0
                }

        logger.info(f"Scan completed. Success: {results['successful_scans']}, "
                   f"Failed: {results['failed_scans']}, "
                   f"Updates: {results['total_updates']}, "
                   f"MRs: {results['merge_requests_created']}")

        return results

    def _scan_repository(self, repo_path: str) -> Dict[str, Any]:
        """Scan a single repository for dependency updates.

        Args:
            repo_path: Repository path (group/project)

        Returns:
            Repository scan results
        """
        result = {
            'success': False,
            'updates_found': 0,
            'merge_requests_created': 0,
            'dockerfiles_scanned': 0,
            'dependencies_found': 0,
            'updates': []
        }

        # Get default branch
        default_branch = self.gitlab_client.get_default_branch(repo_path)

        # Find Dockerfiles in repository
        dockerfiles = self.gitlab_client.list_dockerfiles(repo_path, default_branch)
        result['dockerfiles_scanned'] = len(dockerfiles)

        if not dockerfiles:
            logger.info(f"No Dockerfiles found in {repo_path}")
            result['success'] = True
            return result

        logger.info(f"Found {len(dockerfiles)} Dockerfiles in {repo_path}")

        all_updates = []

        # Scan each Dockerfile
        for dockerfile_path in dockerfiles:
            try:
                dockerfile_updates = self._scan_dockerfile(repo_path, dockerfile_path, default_branch)
                all_updates.extend(dockerfile_updates)
                result['dependencies_found'] += len([u for u in dockerfile_updates if u.get('dependency')])

            except Exception as e:
                logger.error(f"Failed to scan {dockerfile_path} in {repo_path}: {e}")

        # Group updates by dependency and create merge requests
        grouped_updates = self._group_updates(all_updates)
        result['updates_found'] = len(grouped_updates)

        for group_name, updates in grouped_updates.items():
            try:
                if self.config.create_mrs:
                    mr_created = self._create_merge_request_for_updates(repo_path, updates, default_branch)
                    if mr_created:
                        result['merge_requests_created'] += 1
                        result['updates'].append({
                            'group': group_name,
                            'updates': len(updates),
                            'merge_request_created': True
                        })
                    else:
                        result['updates'].append({
                            'group': group_name,
                            'updates': len(updates),
                            'merge_request_created': False
                        })
                else:
                    logger.info(f"Skipping MR creation for {group_name} (createMRs=false)")
                    result['updates'].append({
                        'group': group_name,
                        'updates': len(updates),
                        'merge_request_created': False
                    })

            except Exception as e:
                logger.error(f"Failed to create MR for {group_name} in {repo_path}: {e}")

        result['success'] = True
        return result

    def _scan_dockerfile(self, repo_path: str, dockerfile_path: str, branch: str) -> List[Dict[str, Any]]:
        """Scan a single Dockerfile for dependency updates.

        Args:
            repo_path: Repository path
            dockerfile_path: Path to Dockerfile
            branch: Branch name

        Returns:
            List of updates found
        """
        updates = []

        # Get Dockerfile content
        dockerfile_content = self.gitlab_client.get_file_content(repo_path, dockerfile_path, branch)
        if not dockerfile_content:
            logger.warning(f"Could not read {dockerfile_path} from {repo_path}")
            return updates

        # Parse dependencies
        dependencies = self.dockerfile_parser.extract_dependencies(dockerfile_content, dockerfile_path)

        logger.info(f"Found {len(dependencies)} dependencies in {dockerfile_path}")

        # Check for updates
        for dep in dependencies:
            if dep.skip_reason:
                logger.debug(f"Skipping {dep.dep_name}: {dep.skip_reason}")
                continue

            try:
                dep_updates = self._check_dependency_updates(dep)
                for update in dep_updates:
                    updates.append({
                        'dependency': dep,
                        'update': update,
                        'dockerfile_path': dockerfile_path
                    })

            except Exception as e:
                logger.error(f"Failed to check updates for {dep.dep_name}: {e}")

        return updates

    def _check_dependency_updates(self, dependency: DockerDependency) -> List[VersionUpdate]:
        """Check for updates for a specific dependency.

        Args:
            dependency: Docker dependency

        Returns:
            List of available updates
        """
        # Get registry configuration
        registry_config = self._get_registry_config_for_dependency(dependency)

        # Check cache first
        cache_key = f"tags:{dependency.dep_name}"
        cached_tags = self.cache.get(cache_key)

        if cached_tags is None:
            # Get available tags from registry
            try:
                tags = self.docker_client.get_available_tags(
                    dependency.dep_name,
                    registry_config,
                    max_tags=100
                )
                tag_names = [tag.name for tag in tags]

                # Cache for 1 hour
                self.cache.set(cache_key, tag_names, ttl=3600)
                cached_tags = tag_names

            except Exception as e:
                logger.error(f"Failed to get tags for {dependency.dep_name}: {e}")
                return []

        # Find updates
        updates = self.version_manager.find_updates(
            dependency.current_value,
            cached_tags,
            dependency.current_digest
        )

        # Filter updates based on rules
        filtered_updates = []
        for update in updates:
            if self.version_manager.should_create_update(update):
                filtered_updates.append(update)

        logger.info(f"Found {len(filtered_updates)} updates for {dependency.dep_name}")
        return filtered_updates

    def _get_registry_config_for_dependency(self, dependency: DockerDependency):
        """Get registry configuration for a dependency.

        Args:
            dependency: Docker dependency

        Returns:
            Registry configuration
        """
        # Determine registry URL
        if '/' in dependency.dep_name and not dependency.dep_name.startswith('library/'):
            # Extract registry from image name
            parts = dependency.dep_name.split('/')
            if '.' in parts[0] or ':' in parts[0]:
                # First part looks like a registry
                registry_host = parts[0]
                registry_url = f"https://{registry_host}"
            else:
                # Default to Docker Hub
                registry_url = "https://index.docker.io"
        else:
            # Default to Docker Hub
            registry_url = "https://index.docker.io"

        # Find matching host rule
        host_rule = None
        for rule in self.config.host_rules:
            if rule.match_host in registry_url:
                host_rule = rule
                break

        return create_registry_config(
            registry_url=registry_url,
            username=host_rule.username if host_rule else None,
            password=host_rule.password if host_rule else None,
            token=host_rule.token if host_rule else None
        )

    def _group_updates(self, updates: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group updates for merge request creation.

        Args:
            updates: List of all updates

        Returns:
            Dictionary of grouped updates
        """
        grouped = {}

        for update_info in updates:
            dep = update_info['dependency']
            update = update_info['update']

            # Group by dependency name
            group_key = dep.dep_name

            if group_key not in grouped:
                grouped[group_key] = []

            grouped[group_key].append(update_info)

        return grouped

    def _create_merge_request_for_updates(self, repo_path: str, updates: List[Dict[str, Any]],
                                        default_branch: str) -> bool:
        """Create merge request for a group of updates.

        Args:
            repo_path: Repository path
            updates: List of updates for the same dependency
            default_branch: Default branch name

        Returns:
            True if MR created successfully
        """
        if not updates:
            return False

        # Get the dependency name from first update
        dep_name = updates[0]['dependency'].dep_name
        branch_name = f"evergreen/{dep_name.replace('/', '-')}-{int(time.time())}"

        # Create branch
        if not self.gitlab_client.create_branch(repo_path, branch_name, default_branch):
            return False

        # Apply updates to files
        file_changes = []
        for update_info in updates:
            dep = update_info['dependency']
            update = update_info['update']
            dockerfile_path = update_info['dockerfile_path']

            # Get current file content
            current_content = self.gitlab_client.get_file_content(repo_path, dockerfile_path, default_branch)
            if not current_content:
                continue

            # Apply update
            new_content = self._apply_update_to_dockerfile(current_content, dep, update)
            if new_content != current_content:
                file_changes.append(FileChange(
                    file_path=dockerfile_path,
                    content=new_content,
                    action="update"
                ))

        if not file_changes:
            logger.warning(f"No file changes generated for {dep_name}")
            return False

        # Commit changes
        commit_message = self._generate_commit_message(dep_name, updates)
        if not self.gitlab_client.commit_changes(repo_path, branch_name, commit_message, file_changes):
            return False

        # Create merge request
        mr_title, mr_description = self._generate_mr_content(dep_name, updates)

        # Get assignee IDs
        assignee_ids = []
        for assignee in self.config.assignees:
            user_id = self.gitlab_client.get_user_id(assignee)
            if user_id:
                assignee_ids.append(user_id)

        mr_info = self.gitlab_client.create_merge_request(
            repo_path=repo_path,
            source_branch=branch_name,
            target_branch=default_branch,
            title=mr_title,
            description=mr_description,
            labels=self.config.labels,
            assignee_ids=assignee_ids
        )

        if mr_info:
            logger.info(f"Created merge request: {mr_info.web_url}")
            return True

        return False

    def _apply_update_to_dockerfile(self, content: str, dependency: DockerDependency,
                                  update: VersionUpdate) -> str:
        """Apply version update to Dockerfile content.

        Args:
            content: Original Dockerfile content
            dependency: Dependency to update
            update: Version update

        Returns:
            Updated Dockerfile content
        """
        if not dependency.replace_string:
            return content

        # Build new image reference
        new_image_ref = dependency.dep_name
        if update.new_version:
            new_image_ref += f":{update.new_version}"
        if update.new_digest:
            new_image_ref += f"@{update.new_digest}"

        # Replace in content
        return content.replace(dependency.replace_string, new_image_ref)

    def _generate_commit_message(self, dep_name: str, updates: List[Dict[str, Any]]) -> str:
        """Generate commit message for updates.

        Args:
            dep_name: Dependency name
            updates: List of updates

        Returns:
            Commit message
        """
        if len(updates) == 1:
            update = updates[0]['update']
            return f"Update {dep_name} to {update.new_version}"
        else:
            return f"Update {dep_name} ({len(updates)} files)"

    def _generate_mr_content(self, dep_name: str, updates: List[Dict[str, Any]]) -> tuple:
        """Generate merge request title and description.

        Args:
            dep_name: Dependency name
            updates: List of updates

        Returns:
            Tuple of (title, description)
        """
        title = f"Update {dep_name} Docker image"

        description_lines = [
            f"## Update {dep_name}",
            "",
            "This merge request updates the Docker image dependency:",
            ""
        ]

        for update_info in updates:
            update = update_info['update']
            dockerfile_path = update_info['dockerfile_path']

            if update.current_version:
                description_lines.append(
                    f"- `{dockerfile_path}`: {update.current_version} → {update.new_version}"
                )
            else:
                description_lines.append(
                    f"- `{dockerfile_path}`: Pin to {update.new_version}"
                )

        description_lines.extend([
            "",
            "---",
            "*This merge request was created automatically by evergreen-python.*"
        ])

        return title, "\n".join(description_lines)


@click.command()
@click.option('--config', '-c', help='Configuration file path')
@click.option('--repository', '-r', multiple=True, help='Repository to scan (can be used multiple times)')
@click.option('--dry-run', is_flag=True, help='Perform dry run without creating merge requests')
def main(config: str, repository: tuple, dry_run: bool):
    """Evergreen-Python: Automated Docker dependency updates for GitLab."""
    try:
        # Initialize application
        app = EvergreenPython(config_path=config)

        # Override create_mrs if dry_run
        if dry_run:
            app.config.create_mrs = False
            logger.info("Running in dry-run mode - no merge requests will be created")

        # Run scan
        repositories = list(repository) if repository else None
        results = app.run_scan(repositories)

        # Print summary
        click.echo(f"\n=== Scan Results ===")
        click.echo(f"Repositories scanned: {results['total_repositories']}")
        click.echo(f"Successful scans: {results['successful_scans']}")
        click.echo(f"Failed scans: {results['failed_scans']}")
        click.echo(f"Total updates found: {results['total_updates']}")
        click.echo(f"Merge requests created: {results['merge_requests_created']}")

        # Exit with error code if any scans failed
        if results['failed_scans'] > 0:
            sys.exit(1)

    except Exception as e:
        logger.error(f"Application error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()