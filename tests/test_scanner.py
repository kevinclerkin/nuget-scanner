import os
import zipfile
import xml.etree.ElementTree as ET
from unittest.mock import patch, MagicMock
import pytest
from scanner import get_nuspec_metadata, check_vulnerabilities, scan_nuget_packages

def create_mock_nupkg(file_path, nuspec_content):
    with zipfile.ZipFile(file_path, 'w') as zf:
        zf.writestr('package.nuspec', nuspec_content)


def test_extract_nuspec_metadata(tmp_path):
    nupkg_path = tmp_path / "test_package.nupkg"
    nuspec_content = '''<?xml version="1.0"?>
                        <package>
                            <metadata>
                                <id>TestPackage</id>
                                <version>1.0.0</version>
                            </metadata>
                        </package>'''
    create_mock_nupkg(nupkg_path, nuspec_content)
    