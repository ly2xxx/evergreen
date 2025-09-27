"""GitLab client for repository operations and merge request management."""

import gitlab
from typing import List, Optional, Dict, Any, Tuple
from dataclasses import dataclass
import base64
import logging
from urllib.parse import quote_plus

logger = logging.getLogger(__name__)


@dataclass
class FileChange:
    """Represents a file change in a repository."""
    file_path: str
    content: str
    action: str = "update"  # create, update, delete


@dataclass
class MergeRequestInfo:
    """Information about a merge request."""
    iid: int
    title: str
    description: str
    source_branch: str
    target_branch: str
    state: str
    web_url: str


class GitLabClient:
    """Client for GitLab repository operations."""

    def __init__(self, gitlab_url: str, access_token: str):
        """Initialize GitLab client.

        Args:
            gitlab_url: GitLab instance URL
            access_token: GitLab access token
        """
        self.gitlab_url = gitlab_url
        self.access_token = access_token
        self.gl = gitlab.Gitlab(gitlab_url, private_token=access_token)

    def get_project(self, project_path: str):
        """Get GitLab project.

        Args:
            project_path: Project path (group/project)

        Returns:
            GitLab project object

        Raises:
            gitlab.GitlabError: If project not found or access denied
        """
        try:
            return self.gl.projects.get(project_path)
        except gitlab.GitlabGetError as e:
            logger.error(f"Failed to get project {project_path}: {e}")
            raise

    def get_file_content(self, project_path: str, file_path: str, branch: str = "main") -> Optional[str]:
        """Get file content from repository.

        Args:
            project_path: Project path (group/project)
            file_path: Path to file in repository
            branch: Branch name

        Returns:
            File content or None if not found
        """
        try:
            project = self.get_project(project_path)
            file_obj = project.files.get(file_path=file_path, ref=branch)

            # Decode base64 content
            content = base64.b64decode(file_obj.content).decode('utf-8')
            return content

        except gitlab.GitlabGetError as e:
            if e.response_code == 404:
                logger.debug(f"File {file_path} not found in {project_path}")
                return None
            logger.error(f"Failed to get file {file_path} from {project_path}: {e}")
            raise

    def list_dockerfiles(self, project_path: str, branch: str = "main") -> List[str]:
        """List Dockerfile paths in repository.

        Args:
            project_path: Project path (group/project)
            branch: Branch name

        Returns:
            List of Dockerfile paths
        """
        dockerfiles = []

        try:
            project = self.get_project(project_path)

            # Search for files matching Dockerfile patterns
            dockerfile_patterns = [
                "Dockerfile",
                "dockerfile",
                "Containerfile",
                "containerfile"
            ]

            # Get repository tree
            def search_tree(path="", tree_items=None):
                if tree_items is None:
                    tree_items = project.repository_tree(ref=branch, path=path, recursive=True, all=True)

                for item in tree_items:
                    if item['type'] == 'blob':
                        file_name = item['name']
                        file_path = item['path']

                        # Check if file matches Dockerfile patterns
                        if (file_name in dockerfile_patterns or
                            file_name.startswith('Dockerfile.') or
                            file_name.startswith('dockerfile.') or
                            file_name.endswith('.dockerfile') or
                            file_name.endswith('.Dockerfile')):
                            dockerfiles.append(file_path)

            search_tree()

        except gitlab.GitlabError as e:
            logger.error(f"Failed to list Dockerfiles in {project_path}: {e}")

        return dockerfiles

    def branch_exists(self, project_path: str, branch_name: str) -> bool:
        """Check if branch exists.

        Args:
            project_path: Project path (group/project)
            branch_name: Branch name

        Returns:
            True if branch exists
        """
        try:
            project = self.get_project(project_path)
            project.branches.get(branch_name)
            return True
        except gitlab.GitlabGetError:
            return False

    def create_branch(self, project_path: str, branch_name: str, source_branch: str = "main") -> bool:
        """Create a new branch.

        Args:
            project_path: Project path (group/project)
            branch_name: Name for new branch
            source_branch: Source branch to branch from

        Returns:
            True if branch created successfully
        """
        try:
            project = self.get_project(project_path)

            # Check if branch already exists
            if self.branch_exists(project_path, branch_name):
                logger.info(f"Branch {branch_name} already exists in {project_path}")
                return True

            # Create new branch
            project.branches.create({
                'branch': branch_name,
                'ref': source_branch
            })

            logger.info(f"Created branch {branch_name} in {project_path}")
            return True

        except gitlab.GitlabError as e:
            logger.error(f"Failed to create branch {branch_name} in {project_path}: {e}")
            return False

    def commit_changes(self, project_path: str, branch: str, commit_message: str,
                      file_changes: List[FileChange]) -> bool:
        """Commit file changes to repository.

        Args:
            project_path: Project path (group/project)
            branch: Branch to commit to
            commit_message: Commit message
            file_changes: List of file changes

        Returns:
            True if commit successful
        """
        try:
            project = self.get_project(project_path)

            # Build commit actions
            actions = []
            for change in file_changes:
                action = {
                    'action': change.action,
                    'file_path': change.file_path,
                    'content': change.content
                }
                actions.append(action)

            # Create commit
            commit_data = {
                'branch': branch,
                'commit_message': commit_message,
                'actions': actions
            }

            commit = project.commits.create(commit_data)
            logger.info(f"Created commit {commit.short_id} in {project_path}")
            return True

        except gitlab.GitlabError as e:
            logger.error(f"Failed to commit changes to {project_path}: {e}")
            return False

    def create_merge_request(self, project_path: str, source_branch: str, target_branch: str,
                           title: str, description: str, labels: List[str] = None,
                           assignee_ids: List[int] = None) -> Optional[MergeRequestInfo]:
        """Create a merge request.

        Args:
            project_path: Project path (group/project)
            source_branch: Source branch
            target_branch: Target branch
            title: MR title
            description: MR description
            labels: List of labels to add
            assignee_ids: List of assignee user IDs

        Returns:
            Merge request info or None if failed
        """
        try:
            project = self.get_project(project_path)

            # Check if MR already exists
            existing_mrs = project.mergerequests.list(
                source_branch=source_branch,
                target_branch=target_branch,
                state='opened'
            )

            if existing_mrs:
                mr = existing_mrs[0]
                logger.info(f"Merge request already exists: {mr.web_url}")
                return MergeRequestInfo(
                    iid=mr.iid,
                    title=mr.title,
                    description=mr.description,
                    source_branch=mr.source_branch,
                    target_branch=mr.target_branch,
                    state=mr.state,
                    web_url=mr.web_url
                )

            # Create merge request
            mr_data = {
                'source_branch': source_branch,
                'target_branch': target_branch,
                'title': title,
                'description': description
            }

            if labels:
                mr_data['labels'] = labels

            if assignee_ids:
                mr_data['assignee_ids'] = assignee_ids

            mr = project.mergerequests.create(mr_data)

            logger.info(f"Created merge request: {mr.web_url}")

            return MergeRequestInfo(
                iid=mr.iid,
                title=mr.title,
                description=mr.description,
                source_branch=mr.source_branch,
                target_branch=mr.target_branch,
                state=mr.state,
                web_url=mr.web_url
            )

        except gitlab.GitlabError as e:
            logger.error(f"Failed to create merge request in {project_path}: {e}")
            return None

    def get_user_id(self, username: str) -> Optional[int]:
        """Get user ID by username.

        Args:
            username: GitLab username

        Returns:
            User ID or None if not found
        """
        try:
            users = self.gl.users.list(username=username)
            if users:
                return users[0].id
        except gitlab.GitlabError as e:
            logger.error(f"Failed to get user ID for {username}: {e}")

        return None

    def get_project_labels(self, project_path: str) -> List[str]:
        """Get available labels for a project.

        Args:
            project_path: Project path (group/project)

        Returns:
            List of label names
        """
        try:
            project = self.get_project(project_path)
            labels = project.labels.list(all=True)
            return [label.name for label in labels]
        except gitlab.GitlabError as e:
            logger.error(f"Failed to get labels for {project_path}: {e}")
            return []

    def create_project_label(self, project_path: str, label_name: str, color: str = "#0066CC") -> bool:
        """Create a project label.

        Args:
            project_path: Project path (group/project)
            label_name: Label name
            color: Label color (hex)

        Returns:
            True if label created or already exists
        """
        try:
            project = self.get_project(project_path)

            # Check if label already exists
            existing_labels = self.get_project_labels(project_path)
            if label_name in existing_labels:
                return True

            # Create label
            project.labels.create({
                'name': label_name,
                'color': color
            })

            logger.info(f"Created label '{label_name}' in {project_path}")
            return True

        except gitlab.GitlabError as e:
            logger.error(f"Failed to create label '{label_name}' in {project_path}: {e}")
            return False

    def update_file(self, project_path: str, file_path: str, content: str,
                   branch: str, commit_message: str) -> bool:
        """Update a single file in repository.

        Args:
            project_path: Project path (group/project)
            file_path: Path to file
            content: New file content
            branch: Branch to update
            commit_message: Commit message

        Returns:
            True if file updated successfully
        """
        file_change = FileChange(
            file_path=file_path,
            content=content,
            action="update"
        )

        return self.commit_changes(project_path, branch, commit_message, [file_change])

    def get_default_branch(self, project_path: str) -> str:
        """Get the default branch of a project.

        Args:
            project_path: Project path (group/project)

        Returns:
            Default branch name
        """
        try:
            project = self.get_project(project_path)
            return project.default_branch
        except gitlab.GitlabError as e:
            logger.error(f"Failed to get default branch for {project_path}: {e}")
            return "main"  # Fallback to main