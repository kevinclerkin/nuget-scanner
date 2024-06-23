import zipfile
import os
import sys
import requests
import xml.etree.ElementTree as ET

def get_nuspec_metadata(package_path):
    with zipfile.ZipFile(package_path, 'r') as zf:
        for file_info in zf.infolist():
            if file_info.filename.endswith('.nuspec'):
                with zf.open(file_info) as nuspec_file:
                    tree = ET.parse(nuspec_file)
                    root = tree.getroot()
                    package_id = root.find('.//id').text.strip()
                    package_version = root.find('.//version').text.strip()
                    return package_id, package_version
    return None, None