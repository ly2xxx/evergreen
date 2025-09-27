"""Version manager for Docker image versioning and comparison."""

import re
from typing import List, Optional, Tuple, Set
from dataclasses import dataclass
import semantic_version
import logging
from datetime import datetime
from dateutil import parser as date_parser

logger = logging.getLogger(__name__)


@dataclass
class VersionUpdate:
    """Represents a version update candidate."""
    current_version: Optional[str]
    new_version: str
    new_digest: Optional[str] = None
    update_type: str = "patch"  # major, minor, patch, pin
    release_timestamp: Optional[datetime] = None


class DockerVersionManager:
    """Manages Docker image version comparison and update logic."""

    def __init__(self):
        """Initialize the version manager."""
        # Docker Hub specific patterns
        self.version_patterns = [
            # Semantic versioning patterns
            re.compile(r'^v?(\d+)\.(\d+)\.(\d+)(?:-([a-zA-Z0-9.-]+))?(?:\+([a-zA-Z0-9.-]+))?$'),
            # Major.minor patterns
            re.compile(r'^v?(\d+)\.(\d+)(?:-([a-zA-Z0-9.-]+))?$'),
            # Simple version patterns
            re.compile(r'^v?(\d+)(?:-([a-zA-Z0-9.-]+))?$'),
            # Date-based patterns (YYYY-MM-DD, YYYYMMDD)
            re.compile(r'^(\d{4})-?(\d{2})-?(\d{2})(?:-([a-zA-Z0-9.-]+))?$'),
            # Calendar versioning (YY.M, YYYY.M)
            re.compile(r'^(\d{2,4})\.(\d{1,2})(?:\.(\d+))?(?:-([a-zA-Z0-9.-]+))?$')
        ]

        # Stability indicators (lower = more stable)
        self.stability_order = {
            'stable': 0,
            'release': 0,
            'final': 0,
            'ga': 0,
            '': 0,  # No suffix
            'rc': 1,
            'beta': 2,
            'alpha': 3,
            'dev': 4,
            'snapshot': 4,
            'nightly': 5
        }

        # Tags to skip
        self.skip_tags = {
            'latest', 'edge', 'master', 'main', 'develop', 'dev',
            'nightly', 'unstable', 'experimental'
        }

    def find_updates(self, current_version: Optional[str], available_tags: List[str],
                    current_digest: Optional[str] = None) -> List[VersionUpdate]:
        """Find available updates for a Docker image.

        Args:
            current_version: Current version (tag) of the image
            available_tags: List of available tags from registry
            current_digest: Current digest of the image

        Returns:
            List of version updates, sorted by preference
        """
        updates = []

        # Filter and parse available versions
        valid_versions = self._filter_valid_versions(available_tags)

        if not current_version:
            # If no current version, suggest the latest stable version
            latest_stable = self._find_latest_stable(valid_versions)
            if latest_stable:
                updates.append(VersionUpdate(
                    current_version=current_version,
                    new_version=latest_stable,
                    update_type="pin"
                ))
        else:
            # Find newer versions
            newer_versions = self._find_newer_versions(current_version, valid_versions)

            for version in newer_versions:
                update_type = self._determine_update_type(current_version, version)
                updates.append(VersionUpdate(
                    current_version=current_version,
                    new_version=version,
                    update_type=update_type
                ))

        # Sort updates by preference (patch < minor < major)
        return self._sort_updates(updates)

    def _filter_valid_versions(self, tags: List[str]) -> List[str]:
        """Filter tags to valid versions.

        Args:
            tags: List of all available tags

        Returns:
            List of valid version tags
        """
        valid_versions = []

        for tag in tags:
            # Skip known non-version tags
            if tag.lower() in self.skip_tags:
                continue

            # Skip tags with certain patterns
            if any(pattern in tag.lower() for pattern in ['test', 'debug', 'slim', 'alpine']):
                # Allow alpine and slim variants but note them
                if any(variant in tag.lower() for variant in ['alpine', 'slim']):
                    # Extract base version if possible
                    base_version = self._extract_base_version(tag)
                    if base_version and self._is_valid_version(base_version):
                        valid_versions.append(tag)
                continue

            # Check if tag matches version patterns
            if self._is_valid_version(tag):
                valid_versions.append(tag)

        return valid_versions

    def _extract_base_version(self, tag: str) -> Optional[str]:
        """Extract base version from variant tags like '1.2.3-alpine'.

        Args:
            tag: Tag with potential variant suffix

        Returns:
            Base version or None
        """
        # Common variant patterns
        variant_patterns = [
            r'-alpine$', r'-slim$', r'-buster$', r'-stretch$',
            r'-jessie$', r'-xenial$', r'-bionic$', r'-focal$'
        ]

        for pattern in variant_patterns:
            if re.search(pattern, tag, re.IGNORECASE):
                return re.sub(pattern, '', tag, flags=re.IGNORECASE)

        return None

    def _is_valid_version(self, version: str) -> bool:
        """Check if a string represents a valid version.

        Args:
            version: Version string to check

        Returns:
            True if valid version
        """
        for pattern in self.version_patterns:
            if pattern.match(version):
                return True

        # Try semantic version parsing
        try:
            cleaned_version = version.lstrip('v')
            semantic_version.Version(cleaned_version)
            return True
        except ValueError:
            pass

        return False

    def _find_newer_versions(self, current_version: str, available_versions: List[str]) -> List[str]:
        """Find versions newer than the current version.

        Args:
            current_version: Current version
            available_versions: List of available versions

        Returns:
            List of newer versions
        """
        newer_versions = []

        for version in available_versions:
            if self._is_newer_version(current_version, version):
                newer_versions.append(version)

        return newer_versions

    def _is_newer_version(self, current: str, candidate: str) -> bool:
        """Check if candidate version is newer than current.

        Args:
            current: Current version
            candidate: Candidate version

        Returns:
            True if candidate is newer
        """
        # Try semantic version comparison first
        try:
            current_clean = current.lstrip('v')
            candidate_clean = candidate.lstrip('v')

            # Handle pre-release versions
            current_sem = semantic_version.Version.coerce(current_clean)
            candidate_sem = semantic_version.Version.coerce(candidate_clean)

            if candidate_sem > current_sem:
                return True
            elif candidate_sem == current_sem:
                # If base versions are same, compare stability
                return self._is_more_stable(candidate, current)
            else:
                return False

        except (ValueError, TypeError):
            # Fall back to string comparison for non-semantic versions
            return self._compare_non_semantic(current, candidate)

    def _is_more_stable(self, version1: str, version2: str) -> bool:
        """Compare stability of two versions.

        Args:
            version1: First version
            version2: Second version

        Returns:
            True if version1 is more stable than version2
        """
        stability1 = self._get_stability_level(version1)
        stability2 = self._get_stability_level(version2)

        return stability1 < stability2

    def _get_stability_level(self, version: str) -> int:
        """Get stability level of a version.

        Args:
            version: Version string

        Returns:
            Stability level (lower = more stable)
        """
        version_lower = version.lower()

        for suffix, level in self.stability_order.items():
            if suffix and suffix in version_lower:
                return level

        return self.stability_order['']  # Default to stable

    def _compare_non_semantic(self, current: str, candidate: str) -> bool:
        """Compare non-semantic versions.

        Args:
            current: Current version
            candidate: Candidate version

        Returns:
            True if candidate is newer
        """
        # Try to extract numeric parts and compare
        current_nums = re.findall(r'\d+', current)
        candidate_nums = re.findall(r'\d+', candidate)

        if current_nums and candidate_nums:
            try:
                # Convert to tuples of integers for comparison
                current_tuple = tuple(int(x) for x in current_nums)
                candidate_tuple = tuple(int(x) for x in candidate_nums)
                return candidate_tuple > current_tuple
            except ValueError:
                pass

        # Fall back to string comparison
        return candidate > current

    def _find_latest_stable(self, versions: List[str]) -> Optional[str]:
        """Find the latest stable version from a list.

        Args:
            versions: List of versions

        Returns:
            Latest stable version or None
        """
        if not versions:
            return None

        # Filter out pre-release versions
        stable_versions = []
        for version in versions:
            if self._get_stability_level(version) == 0:  # Stable
                stable_versions.append(version)

        if not stable_versions:
            # If no stable versions, use all versions
            stable_versions = versions

        # Sort and return latest
        try:
            sorted_versions = sorted(
                stable_versions,
                key=lambda v: semantic_version.Version.coerce(v.lstrip('v')),
                reverse=True
            )
            return sorted_versions[0]
        except (ValueError, TypeError):
            # Fall back to string sorting
            return sorted(stable_versions, reverse=True)[0]

    def _determine_update_type(self, current: str, new: str) -> str:
        """Determine the type of update (major, minor, patch).

        Args:
            current: Current version
            new: New version

        Returns:
            Update type string
        """
        try:
            current_clean = current.lstrip('v')
            new_clean = new.lstrip('v')

            current_sem = semantic_version.Version.coerce(current_clean)
            new_sem = semantic_version.Version.coerce(new_clean)

            if new_sem.major > current_sem.major:
                return "major"
            elif new_sem.minor > current_sem.minor:
                return "minor"
            elif new_sem.patch > current_sem.patch:
                return "patch"
            else:
                return "patch"  # Default for pre-release updates

        except (ValueError, TypeError):
            # For non-semantic versions, try to guess
            current_nums = re.findall(r'\d+', current)
            new_nums = re.findall(r'\d+', new)

            if len(current_nums) >= 1 and len(new_nums) >= 1:
                if int(new_nums[0]) > int(current_nums[0]):
                    return "major"
                elif len(current_nums) >= 2 and len(new_nums) >= 2:
                    if int(new_nums[1]) > int(current_nums[1]):
                        return "minor"

            return "patch"

    def _sort_updates(self, updates: List[VersionUpdate]) -> List[VersionUpdate]:
        """Sort updates by preference.

        Args:
            updates: List of updates

        Returns:
            Sorted list of updates
        """
        # Sort by update type priority: patch < minor < major
        type_priority = {"patch": 0, "minor": 1, "major": 2, "pin": 3}

        return sorted(
            updates,
            key=lambda u: (
                type_priority.get(u.update_type, 4),
                u.new_version
            )
        )

    def should_create_update(self, update: VersionUpdate, update_rules: Optional[dict] = None) -> bool:
        """Determine if an update should be created based on rules.

        Args:
            update: Version update candidate
            update_rules: Update rules configuration

        Returns:
            True if update should be created
        """
        if update_rules is None:
            update_rules = {}

        # Check if update type is allowed
        allowed_types = update_rules.get('allowed_update_types', ['patch', 'minor', 'major'])
        if update.update_type not in allowed_types:
            return False

        # Check if version passes additional filters
        version_patterns = update_rules.get('version_patterns', [])
        if version_patterns:
            for pattern in version_patterns:
                if not re.search(pattern, update.new_version):
                    return False

        return True