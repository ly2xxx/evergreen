"""Dockerfile parser to extract Docker image dependencies."""

import re
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class DockerDependency:
    """Represents a Docker image dependency."""
    dep_name: str
    package_name: str
    current_value: Optional[str] = None
    current_digest: Optional[str] = None
    dep_type: str = "stage"
    skip_reason: Optional[str] = None
    replace_string: Optional[str] = None
    line_number: Optional[int] = None
    raw_line: Optional[str] = None


class DockerfileParser:
    """Parser for extracting Docker dependencies from Dockerfiles."""

    def __init__(self):
        """Initialize the parser."""
        self.variable_marker = "$"

        # Special prefixes that should be cleaned up
        self.special_prefixes = ["amd64", "arm64", "library"]

        # Regex patterns based on Renovate's implementation
        self.escape_directive_pattern = re.compile(
            r"^[ \t]*#[ \t]*(?P<directive>syntax|escape)[ \t]*=[ \t]*(?P<escapeChar>\S)",
            re.IGNORECASE
        )

        self.syntax_pattern = re.compile(
            r"^#[ \t]*syntax[ \t]*=[ \t]*(?P<image>\S+)",
            re.IGNORECASE | re.MULTILINE
        )

        self.variable_pattern = re.compile(
            r"(?P<fullvariable>\\?\$(?P<simplearg>\w+)|\\?\${(?P<complexarg>\w+)(?::.+?)?}+)",
            re.IGNORECASE
        )

        self.default_value_pattern = re.compile(r"^\${.+?:-\"?(?P<value>.*?)\"?}$")

        self.quay_pattern = re.compile(r"^quay\.io(?::[1-9][0-9]{0,4})?", re.IGNORECASE)

    def extract_dependencies(self, dockerfile_content: str, file_path: str = "Dockerfile") -> List[DockerDependency]:
        """Extract Docker dependencies from Dockerfile content.

        Args:
            dockerfile_content: Content of the Dockerfile
            file_path: Path to the Dockerfile (for logging)

        Returns:
            List of Docker dependencies found
        """
        # Remove BOM marker if present
        content = dockerfile_content.replace('\ufeff', '')

        dependencies = []
        stage_names = set()
        args = {}

        escape_char = "\\\\"
        look_for_escape_char = True
        look_for_syntax_directive = True

        # Determine line ending style
        line_feed = '\r\n' if '\r\n' in content else '\n'
        lines = content.split('\n')

        line_number = 0
        while line_number < len(lines):
            line_start = line_number
            instruction = lines[line_number]

            # Check for escape directive
            if look_for_escape_char:
                match = self.escape_directive_pattern.match(instruction)
                if not match:
                    look_for_escape_char = False
                elif match.group('directive').lower() == 'escape':
                    if match.group('escapeChar') == '`':
                        escape_char = '`'
                    look_for_escape_char = False

            # Check for syntax directive
            if look_for_syntax_directive:
                match = self.syntax_pattern.match(instruction)
                if match:
                    syntax_image = match.group('image')
                    dep = self._create_dependency(syntax_image, line_start + 1, instruction)
                    if dep:
                        dep.dep_type = 'syntax'
                        dependencies.append(dep)
                        logger.debug(f"Found syntax dependency: {dep.dep_name}")
                look_for_syntax_directive = False

            # Handle line continuations
            line_continuation_pattern = re.compile(rf"{re.escape(escape_char)}[ \t]*$|^[ \t]*#", re.MULTILINE)
            line_lookahead = instruction

            while (not look_for_escape_char and
                   not instruction.lstrip().startswith('#') and
                   line_continuation_pattern.search(line_lookahead)):
                line_number += 1
                if line_number < len(lines):
                    line_lookahead = lines[line_number]
                    instruction += '\n' + line_lookahead
                else:
                    break

            # Extract ARG instructions
            arg_match = self._extract_arg(instruction, escape_char)
            if arg_match:
                args[arg_match[0]] = arg_match[1]

            # Extract FROM instructions
            from_dep = self._extract_from(instruction, escape_char, args, stage_names, line_start + 1)
            if from_dep:
                dependencies.append(from_dep)

            # Extract COPY --from instructions
            copy_dep = self._extract_copy_from(instruction, escape_char, stage_names, line_start + 1)
            if copy_dep:
                dependencies.append(copy_dep)

            # Extract RUN --mount=from instructions
            run_dep = self._extract_run_mount_from(instruction, escape_char, stage_names, line_start + 1)
            if run_dep:
                dependencies.append(run_dep)

            line_number += 1

        # Set dep types
        if dependencies:
            for dep in dependencies[:-1]:
                if dep.dep_type == "stage":
                    dep.dep_type = "stage"
            dependencies[-1].dep_type = "final"

        logger.info(f"Extracted {len(dependencies)} dependencies from {file_path}")
        return dependencies

    def _extract_arg(self, instruction: str, escape_char: str) -> Optional[Tuple[str, str]]:
        """Extract ARG instruction values.

        Args:
            instruction: Dockerfile instruction
            escape_char: Escape character

        Returns:
            Tuple of (arg_name, arg_value) or None
        """
        arg_pattern = re.compile(
            rf"^[ \t]*ARG(?:{re.escape(escape_char)}[ \t]*\r?\n| |\t|#.*?\r?\n)+(?P<name>\w+)[ =](?P<value>\S*)",
            re.IGNORECASE | re.MULTILINE
        )

        match = arg_pattern.search(instruction)
        if match:
            name = match.group('name')
            value = match.group('value')

            # Remove quotes if present
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]

            return (name, value or '')

        return None

    def _extract_from(self, instruction: str, escape_char: str, args: Dict[str, str],
                     stage_names: Set[str], line_number: int) -> Optional[DockerDependency]:
        """Extract FROM instruction dependencies.

        Args:
            instruction: Dockerfile instruction
            escape_char: Escape character
            args: ARG variables
            stage_names: Set of stage names
            line_number: Line number in file

        Returns:
            Docker dependency or None
        """
        from_pattern = re.compile(
            rf"^[ \t]*FROM(?:{re.escape(escape_char)}[ \t]*\r?\n| |\t|#.*?\r?\n|--platform=\S+)+(?P<image>\S+)(?:(?:{re.escape(escape_char)}[ \t]*\r?\n| |\t|#.*?\r?\n)+as[ \t]+(?P<name>\S+))?",
            re.IGNORECASE | re.MULTILINE
        )

        match = from_pattern.search(instruction)
        if not match:
            return None

        from_image = match.group('image')
        stage_name = match.group('name')

        # Resolve variables
        if self.variable_marker in from_image:
            from_image = self._resolve_variables(from_image, args)
            if self.variable_marker in from_image:
                # Still contains unresolved variables
                return DockerDependency(
                    dep_name="",
                    package_name="",
                    skip_reason="contains-variable",
                    line_number=line_number,
                    raw_line=instruction
                )

        # Add stage name if present
        if stage_name:
            logger.debug(f"Found multistage build stage: {stage_name}")
            stage_names.add(stage_name)

        # Skip special cases
        if from_image == 'scratch':
            logger.debug("Skipping 'scratch' image")
            return None

        if from_image in stage_names:
            logger.debug(f"Skipping stage alias: {from_image}")
            return None

        return self._create_dependency(from_image, line_number, instruction)

    def _extract_copy_from(self, instruction: str, escape_char: str,
                          stage_names: Set[str], line_number: int) -> Optional[DockerDependency]:
        """Extract COPY --from instruction dependencies.

        Args:
            instruction: Dockerfile instruction
            escape_char: Escape character
            stage_names: Set of stage names
            line_number: Line number in file

        Returns:
            Docker dependency or None
        """
        copy_pattern = re.compile(
            rf"^[ \t]*COPY(?:{re.escape(escape_char)}[ \t]*\r?\n| |\t|#.*?\r?\n|--[a-z]+(?:=[a-zA-Z0-9_.:-]+?)?)+--from=(?P<image>\S+)",
            re.IGNORECASE | re.MULTILINE
        )

        match = copy_pattern.search(instruction)
        if not match:
            return None

        image = match.group('image')

        # Skip stage references
        if image in stage_names:
            logger.debug(f"Skipping COPY --from stage alias: {image}")
            return None

        # Skip numeric references (stage indexes)
        if image.isdigit():
            logger.debug(f"Skipping COPY --from index reference: {image}")
            return None

        return self._create_dependency(image, line_number, instruction)

    def _extract_run_mount_from(self, instruction: str, escape_char: str,
                               stage_names: Set[str], line_number: int) -> Optional[DockerDependency]:
        """Extract RUN --mount=from instruction dependencies.

        Args:
            instruction: Dockerfile instruction
            escape_char: Escape character
            stage_names: Set of stage names
            line_number: Line number in file

        Returns:
            Docker dependency or None
        """
        run_pattern = re.compile(
            rf"^[ \t]*RUN(?:{re.escape(escape_char)}[ \t]*\r?\n| |\t|#.*?\r?\n|--[a-z]+(?:=[a-zA-Z0-9_.:-]+?)?)+--mount=(?:\S*=\S*,)*from=(?P<image>[^, ]+)",
            re.IGNORECASE | re.MULTILINE
        )

        match = run_pattern.search(instruction)
        if not match:
            return None

        image = match.group('image')

        # Skip stage references
        if image in stage_names:
            logger.debug(f"Skipping RUN --mount=from stage alias: {image}")
            return None

        return self._create_dependency(image, line_number, instruction)

    def _resolve_variables(self, image: str, args: Dict[str, str]) -> str:
        """Resolve ARG variables in image string.

        Args:
            image: Image string with variables
            args: ARG variables

        Returns:
            Image string with variables resolved
        """
        variables = self._extract_variables(image)
        resolved_image = image

        for full_variable, arg_name in variables.items():
            if arg_name in args:
                resolved_image = resolved_image.replace(full_variable, args[arg_name])

        return resolved_image

    def _extract_variables(self, image: str) -> Dict[str, str]:
        """Extract variables from image string.

        Args:
            image: Image string

        Returns:
            Dictionary mapping full variable to variable name
        """
        variables = {}

        for match in self.variable_pattern.finditer(image):
            groups = match.groupdict()
            if groups['fullvariable']:
                variables[groups['fullvariable']] = (
                    groups.get('simplearg') or groups.get('complexarg')
                )

        return variables

    def _create_dependency(self, image: str, line_number: int, raw_line: str) -> Optional[DockerDependency]:
        """Create a DockerDependency from an image string.

        Args:
            image: Docker image string
            line_number: Line number in file
            raw_line: Raw line content

        Returns:
            DockerDependency or None if invalid
        """
        if not image or not image.strip():
            return DockerDependency(
                dep_name="",
                package_name="",
                skip_reason="invalid-value",
                line_number=line_number,
                raw_line=raw_line
            )

        # Handle default value variables
        if image.startswith('${') and ':-' in image:
            match = self.default_value_pattern.match(image)
            if match:
                image = match.group('value')
            else:
                return DockerDependency(
                    dep_name="",
                    package_name="",
                    skip_reason="contains-variable",
                    line_number=line_number,
                    raw_line=raw_line
                )

        # Split image into parts: name:tag@digest
        dep_name, current_value, current_digest = self._split_image_parts(image)

        # Clean up special prefixes
        for prefix in self.special_prefixes:
            if dep_name.startswith(f"{prefix}/"):
                dep_name = dep_name.replace(f"{prefix}/", "")
                break

        # Clean up quay.io ports
        if self.quay_pattern.match(dep_name):
            dep_name = self.quay_pattern.sub("quay.io", dep_name)

        return DockerDependency(
            dep_name=dep_name,
            package_name=dep_name,
            current_value=current_value,
            current_digest=current_digest,
            replace_string=image,
            line_number=line_number,
            raw_line=raw_line
        )

    def _split_image_parts(self, image: str) -> Tuple[str, Optional[str], Optional[str]]:
        """Split image string into name, tag, and digest.

        Args:
            image: Docker image string

        Returns:
            Tuple of (dep_name, current_value, current_digest)
        """
        # Split by @ to separate digest
        parts = image.split('@', 1)
        image_with_tag = parts[0]
        current_digest = parts[1] if len(parts) > 1 else None

        # Split by : to separate tag
        tag_parts = image_with_tag.split(':')

        # If only one part or last part contains '/', it's all part of the name
        if len(tag_parts) == 1 or '/' in tag_parts[-1]:
            dep_name = image_with_tag
            current_value = None
        else:
            current_value = tag_parts[-1]
            dep_name = ':'.join(tag_parts[:-1])

        return dep_name, current_value, current_digest