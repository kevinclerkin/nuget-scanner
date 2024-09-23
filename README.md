# NuGet Scanner

A command-line tool to scan NuGet packages for security vulnerabilities. Extracts metadata from NuGet packages and checks for vulnerabilities using the NVD (National Vulnerability Database).

## Features

- Scans `.nupkg` files in a specified directory.
- Retrieves and parses `.nuspec` files to extract package metadata.
- Checks for vulnerabilities based on package ID and version.
- Provides logging for easy debugging and tracking
