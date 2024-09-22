import zipfile
import os
import requests
import xml.etree.ElementTree as ET
import logging
import argparse

logging.basicConfig(level=logging.INFO)

def get_nuspec_metadata(package_path):
    try:
        with zipfile.ZipFile(package_path, 'r') as zf:
            for file_info in zf.infolist():
                if file_info.filename.endswith('.nuspec'):
                    with zf.open(file_info) as nuspec_file:
                        tree = ET.parse(nuspec_file)
                        root = tree.getroot()
                        package_id = root.find('.//id').text.strip()
                        package_version = root.find('.//version').text.strip()
                        return package_id, package_version
    except (zipfile.BadZipFile, FileNotFoundError) as e:
        logging.error(f"Error reading {package_path}: {e}")
    return None, None

def check_vulnerabilities(package_id, package_version):
    base_url = 'https://services.nvd.nist.gov/rest/json/cves/1.0'
    url = f'{base_url}?keyword={package_id} {package_version}'
    
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        if 'result' in data:
            vulnerabilities = data['result']['CVE_Items']
            if vulnerabilities:
                logging.info(f"Vulnerabilities found for {package_id} {package_version}:")
                for vuln in vulnerabilities:
                    logging.info(f"- {vuln['cve']['CVE_data_meta']['ID']}: {vuln['cve']['description']['description_data'][0]['value']}")
            else:
                logging.info(f"No vulnerabilities found for {package_id} {package_version}")
        else:
            logging.warning(f"No results found for {package_id} {package_version}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Request error: {e}")

def scan_nuget_packages(working_directory):
    nuget_packages_dir = os.path.join(working_directory, 'nuget_packages')
    if not os.path.exists(nuget_packages_dir):
        logging.error(f"Directory not found: {nuget_packages_dir}")
        return

    for root, dirs, files in os.walk(nuget_packages_dir):
        logging.info(f"Scanning directory: {root}")
        logging.info(f"Subdirectories: {dirs}")
        logging.info(f"Files: {files}")
        
        for file in files:
            if file.endswith(".nupkg"):
                package_path = os.path.join(root, file)
                if os.path.getsize(package_path) == 0:
                    logging.warning(f"Empty package file: {package_path}")
                    continue
                package_id, package_version = get_nuspec_metadata(package_path)
                if package_id and package_version:
                    check_vulnerabilities(package_id, package_version)
                else:
                    logging.error(f"Failed to extract package metadata for {package_path}.")

def main():
    parser = argparse.ArgumentParser(description="Scan NuGet packages for vulnerabilities.")
    parser.add_argument("working_directory", help="The directory where NuGet packages are located.")
    args = parser.parse_args()

    if not os.path.isdir(args.working_directory):
        logging.error(f"Invalid directory: {args.working_directory}")
        return

    scan_nuget_packages(args.working_directory)

if __name__ == "__main__":
    main()

