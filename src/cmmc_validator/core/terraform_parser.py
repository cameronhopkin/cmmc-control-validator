#!/usr/bin/env python3
"""
CMMC Control Validator - Terraform Parser
Parse Terraform (.tf) files and extract resource configurations.

Author: Cameron Hopkin
License: MIT
"""
import json
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Iterator
from dataclasses import dataclass, field
import logging

logger = logging.getLogger(__name__)


@dataclass
class TerraformResource:
    """Represents a parsed Terraform resource."""
    resource_type: str
    name: str
    config: Dict
    file_path: str
    line_number: int = 0

    @property
    def full_address(self) -> str:
        """Get full resource address (type.name)."""
        return f"{self.resource_type}.{self.name}"


@dataclass
class TerraformModule:
    """Represents a Terraform module."""
    name: str
    source: str
    config: Dict
    file_path: str


@dataclass
class ParseResult:
    """Result of parsing Terraform files."""
    resources: List[TerraformResource] = field(default_factory=list)
    modules: List[TerraformModule] = field(default_factory=list)
    variables: Dict[str, Dict] = field(default_factory=dict)
    outputs: Dict[str, Dict] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    @property
    def resource_count(self) -> int:
        return len(self.resources)

    def get_resources_by_type(self, resource_type: str) -> List[TerraformResource]:
        """Get all resources of a specific type."""
        return [r for r in self.resources if r.resource_type == resource_type]

    def get_aws_resources(self) -> List[TerraformResource]:
        """Get all AWS resources."""
        return [r for r in self.resources if r.resource_type.startswith("aws_")]


class TerraformParser:
    """
    Parse Terraform configurations.

    Supports parsing both HCL (.tf) and JSON (.tf.json) formats.
    Uses terraform show -json when available for accurate parsing,
    falls back to regex-based parsing otherwise.
    """

    # Regex patterns for HCL parsing
    RESOURCE_PATTERN = re.compile(
        r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{',
        re.MULTILINE
    )

    MODULE_PATTERN = re.compile(
        r'module\s+"([^"]+)"\s*\{',
        re.MULTILINE
    )

    VARIABLE_PATTERN = re.compile(
        r'variable\s+"([^"]+)"\s*\{',
        re.MULTILINE
    )

    def __init__(self, use_terraform_cli: bool = True):
        """
        Initialize parser.

        Args:
            use_terraform_cli: Try to use terraform CLI for parsing
        """
        self.use_terraform_cli = use_terraform_cli
        self._terraform_available = self._check_terraform()

    def _check_terraform(self) -> bool:
        """Check if terraform CLI is available."""
        try:
            result = subprocess.run(
                ["terraform", "version"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def parse_directory(self, directory: str) -> ParseResult:
        """
        Parse all Terraform files in a directory.

        Args:
            directory: Path to directory containing .tf files

        Returns:
            ParseResult with all resources, modules, etc.
        """
        path = Path(directory)
        if not path.is_dir():
            return ParseResult(errors=[f"Not a directory: {directory}"])

        result = ParseResult()

        # Try terraform CLI first if available
        if self.use_terraform_cli and self._terraform_available:
            cli_result = self._parse_with_cli(path)
            if cli_result and not cli_result.errors:
                return cli_result

        # Fall back to manual parsing
        for tf_file in path.glob("**/*.tf"):
            file_result = self._parse_hcl_file(tf_file)
            result.resources.extend(file_result.resources)
            result.modules.extend(file_result.modules)
            result.variables.update(file_result.variables)
            result.errors.extend(file_result.errors)

        # Also parse .tf.json files
        for json_file in path.glob("**/*.tf.json"):
            file_result = self._parse_json_file(json_file)
            result.resources.extend(file_result.resources)
            result.modules.extend(file_result.modules)
            result.errors.extend(file_result.errors)

        return result

    def parse_file(self, filepath: str) -> ParseResult:
        """Parse a single Terraform file."""
        path = Path(filepath)
        if not path.exists():
            return ParseResult(errors=[f"File not found: {filepath}"])

        if path.suffix == ".json" or filepath.endswith(".tf.json"):
            return self._parse_json_file(path)
        else:
            return self._parse_hcl_file(path)

    def _parse_with_cli(self, directory: Path) -> Optional[ParseResult]:
        """Use terraform CLI to parse configuration."""
        try:
            # Initialize if needed
            subprocess.run(
                ["terraform", "init", "-backend=false"],
                cwd=directory,
                capture_output=True,
                timeout=60
            )

            # Get plan in JSON format
            result = subprocess.run(
                ["terraform", "show", "-json"],
                cwd=directory,
                capture_output=True,
                timeout=30
            )

            if result.returncode != 0:
                return None

            data = json.loads(result.stdout)
            return self._parse_terraform_json(data, str(directory))

        except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception) as e:
            logger.warning(f"CLI parsing failed: {e}")
            return None

    def _parse_terraform_json(self, data: Dict, base_path: str) -> ParseResult:
        """Parse terraform show -json output."""
        result = ParseResult()

        # Parse planned values if available
        values = data.get("planned_values", {}).get("root_module", {})

        for resource in values.get("resources", []):
            result.resources.append(TerraformResource(
                resource_type=resource.get("type", ""),
                name=resource.get("name", ""),
                config=resource.get("values", {}),
                file_path=base_path
            ))

        # Parse child modules
        for module in values.get("child_modules", []):
            for resource in module.get("resources", []):
                result.resources.append(TerraformResource(
                    resource_type=resource.get("type", ""),
                    name=resource.get("name", ""),
                    config=resource.get("values", {}),
                    file_path=base_path
                ))

        return result

    def _parse_hcl_file(self, filepath: Path) -> ParseResult:
        """Parse HCL format Terraform file using regex."""
        result = ParseResult()

        try:
            content = filepath.read_text(encoding='utf-8')
        except Exception as e:
            result.errors.append(f"Error reading {filepath}: {e}")
            return result

        # Find all resources
        for match in self.RESOURCE_PATTERN.finditer(content):
            resource_type = match.group(1)
            resource_name = match.group(2)

            # Extract resource block content
            block_start = match.end()
            block_content = self._extract_block(content, block_start)
            config = self._parse_hcl_block(block_content)

            result.resources.append(TerraformResource(
                resource_type=resource_type,
                name=resource_name,
                config=config,
                file_path=str(filepath),
                line_number=content[:match.start()].count('\n') + 1
            ))

        # Find all modules
        for match in self.MODULE_PATTERN.finditer(content):
            module_name = match.group(1)
            block_start = match.end()
            block_content = self._extract_block(content, block_start)
            config = self._parse_hcl_block(block_content)

            result.modules.append(TerraformModule(
                name=module_name,
                source=config.get("source", ""),
                config=config,
                file_path=str(filepath)
            ))

        # Find variables
        for match in self.VARIABLE_PATTERN.finditer(content):
            var_name = match.group(1)
            block_start = match.end()
            block_content = self._extract_block(content, block_start)
            config = self._parse_hcl_block(block_content)
            result.variables[var_name] = config

        return result

    def _parse_json_file(self, filepath: Path) -> ParseResult:
        """Parse JSON format Terraform file."""
        result = ParseResult()

        try:
            with open(filepath) as f:
                data = json.load(f)
        except Exception as e:
            result.errors.append(f"Error parsing {filepath}: {e}")
            return result

        # Parse resources
        for resource_type, resources in data.get("resource", {}).items():
            for name, config in resources.items():
                result.resources.append(TerraformResource(
                    resource_type=resource_type,
                    name=name,
                    config=config if isinstance(config, dict) else {},
                    file_path=str(filepath)
                ))

        # Parse modules
        for name, config in data.get("module", {}).items():
            result.modules.append(TerraformModule(
                name=name,
                source=config.get("source", ""),
                config=config,
                file_path=str(filepath)
            ))

        return result

    def _extract_block(self, content: str, start_pos: int) -> str:
        """Extract content between matching braces."""
        brace_count = 0
        in_string = False
        escape_next = False
        block_start = None

        for i, char in enumerate(content[start_pos:], start_pos):
            if escape_next:
                escape_next = False
                continue

            if char == '\\':
                escape_next = True
                continue

            if char == '"' and not escape_next:
                in_string = not in_string
                continue

            if in_string:
                continue

            if char == '{':
                if block_start is None:
                    block_start = i + 1
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0:
                    return content[block_start:i]

        return ""

    def _parse_hcl_block(self, content: str) -> Dict:
        """Parse HCL block content into a dictionary (simplified)."""
        result = {}

        # Simple key = value pattern
        simple_pattern = re.compile(
            r'^\s*(\w+)\s*=\s*"([^"]*)"',
            re.MULTILINE
        )

        for match in simple_pattern.finditer(content):
            key, value = match.groups()
            result[key] = value

        # Boolean values
        bool_pattern = re.compile(
            r'^\s*(\w+)\s*=\s*(true|false)',
            re.MULTILINE | re.IGNORECASE
        )

        for match in bool_pattern.finditer(content):
            key, value = match.groups()
            result[key] = value.lower() == "true"

        # Check for nested blocks (simplified detection)
        nested_blocks = [
            "server_side_encryption_configuration",
            "versioning",
            "logging",
            "lifecycle_rule",
            "tags",
        ]

        for block_name in nested_blocks:
            if block_name in content:
                result[block_name] = {"_present": True}

        return result


def iterate_resources(directory: str) -> Iterator[TerraformResource]:
    """Convenience function to iterate over all Terraform resources."""
    parser = TerraformParser()
    result = parser.parse_directory(directory)
    yield from result.resources
