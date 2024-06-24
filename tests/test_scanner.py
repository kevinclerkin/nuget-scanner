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
    
    package_id, package_version = get_nuspec_metadata(nupkg_path)
    assert package_id == "TestPackage"
    assert package_version == "1.0.0"

@patch('requests.get')
def test_check_vulnerabilities(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "result": {
            "CVE_Items": [
                {
                    "cve": {
                        "CVE_data_meta": {"ID": "CVE-1234-5678"},
                        "description": {"description_data": [{"value": "Test vulnerability description"}]}
                    }
                }
            ]
        }
    }
    mock_get.return_value = mock_response

    package_id = "TestPackage"
    package_version = "1.0.0"
    
    check_vulnerabilities(package_id, package_version)
    assert mock_get.called