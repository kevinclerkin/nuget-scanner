import os
import zipfile
import xml.etree.ElementTree as ET
from unittest.mock import patch, MagicMock
import pytest
from scanner import get_nuspec_metadata, check_vulnerabilities, scan_nuget_packages

def create_mock_nupkg(file_path, nuspec_content):
    with zipfile.ZipFile(file_path, 'w') as zf:
        zf.writestr('package.nuspec', nuspec_content)