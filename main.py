import os
import subprocess
import shutil
import datetime
import re
import threading
import debian.debfile
from openpyxl import Workbook
from concurrent.futures import ThreadPoolExecutor, as_completed

# Variables for directories and files
output_dir = "/mnt/output"
deb_packages_dir = os.path.join(output_dir, "deb_packages")
sbom_dir = os.path.join(output_dir, "sbom_results")
trivy_results_dir = os.path.join(output_dir, "trivy_results")
logs_dir = os.path.join(output_dir, "logs")
metadata_dir = os.path.join(output_dir, "metadata_results")

download_log_file = os.path.join(logs_dir, "download_log.txt")
sbom_log_file = os.path.join(logs_dir, "sbom_log.txt")
trivy_log_file = os.path.join(logs_dir, "trivy_log.txt")
clamav_log_file = os.path.join(logs_dir, "clamav_log.txt")
metadata_log_file = os.path.join(logs_dir, "metadata_log.txt")

package_list_file = "packages.txt"
repo_list_file = "repos.txt"
urls_file = "urls.txt"
filenames_file = "filenames.txt"
max_threads = 5
scan_threads = 5

# Get Ubuntu version and other environment variables passed from run_script.sh
ubuntu_version = os.getenv("UBUNTU_VERSION", "")
download_mode = os.getenv("DOWNLOAD_MODE", "")
download_file = os.getenv("DOWNLOAD_FILE", "")
base_url = os.getenv("BASE_URL", "")

# Ensure all necessary directories exist
def ensure_directories_exist():
    """Ensure all necessary directories exist."""
    dirs = [output_dir, deb_packages_dir, sbom_dir, trivy_results_dir, logs_dir, metadata_dir]
    for directory in dirs:
        if not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
            os.chmod(directory, 0o777)  # Ensure directories are writable

ensure_directories_exist()

def log_message(message, log_file, level="INFO"):
    """Logs messages to the appropriate log file with timestamps and log levels."""
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(log_file, 'a', encoding='utf-8') as log:
        log.write(f"{timestamp} - {level} - {message}\n")
    print(f"{timestamp} - {level} - {message}")

def update_package_lists():
    """Updates the package lists."""
    log_message("Updating package lists...", download_log_file)
    update_command = subprocess.run(["apt-get", "update"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if update_command.returncode == 0:
        log_message("Package lists updated.", download_log_file)
    else:
        log_message(f"Failed to update package lists: {update_command.stdout}", download_log_file)

def update_clamav_definitions():
    """Updates ClamAV virus definitions."""
    log_message("Updating ClamAV virus definitions...", clamav_log_file)
    try:
        result = subprocess.run(["freshclam"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            log_message("ClamAV virus definitions updated.", clamav_log_file)
        else:
            log_message(f"Failed to update ClamAV definitions: {result.stderr}", clamav_log_file)
    except Exception as e:
        log_message(f"Exception during ClamAV update: {e}", clamav_log_file)

def download_all_packages(retries=3, wait=5):
    """Download all packages listed in the package list file using apt-get download with retries."""
    if not os.path.exists(package_list_file):
        log_message(f"Package list file {package_list_file} does not exist.", download_log_file, "ERROR")
        return

    with open(package_list_file, 'r') as f:
        lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    log_message(f"Total packages to download: {len(lines)}", download_log_file, "INFO")

    for line in lines:
        parts = line.split(',', 1)
        if len(parts) == 2:
            repo_name, package_entry = parts
            repo_name = repo_name.strip()
            package_entry = package_entry.strip()
            log_message(f"Processing package '{package_entry}' from repository '{repo_name}'", download_log_file, "INFO")
        else:
            package_entry = parts[0].strip()
            repo_name = "Unknown"
            log_message(f"Processing package '{package_entry}' without specified repository", download_log_file, "WARNING")

        # Check if package_entry has a version
        if '=' in package_entry:
            package, version = package_entry.split('=', 1)
            package = package.strip()
            version = version.strip()
            package_version = f"{package}={version}"
        else:
            package = package_entry
            package_version = package

        log_message(f"Attempting to download package: {package_version}", download_log_file, "INFO")

        for attempt in range(1, retries + 1):
            try:
                download_command = ["apt-get", "download", package_version]
                result = subprocess.run(download_command, cwd=deb_packages_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if result.returncode == 0:
                    log_message(f"Successfully downloaded {package_version}", download_log_file, "INFO")
                    break
                else:
                    log_message(f"Failed to download {package_version}: {result.stderr}", download_log_file, "ERROR")
            except Exception as e:
                log_message(f"Exception occurred while downloading {package_version}: {e}", download_log_file, "ERROR")

            if attempt < retries:
                log_message(f"Retrying download of {package_version} in {wait} seconds... (Attempt {attempt}/{retries})", download_log_file, "WARNING")
                time.sleep(wait)
            else:
                log_message(f"Failed to download package {package_version} after {retries} attempts.", download_log_file, "ERROR")

    move_deb_files()
    clean_apt_cache()

def move_deb_files():
    """Moves .deb files from APT cache and current directory to the output directory."""
    apt_cache_dir = "/var/cache/apt/archives"

    # Ensure the deb_packages directory exists
    ensure_directories_exist()

    # Move files from APT cache directory
    for file in os.listdir(apt_cache_dir):
        if file.endswith(".deb"):
            src_file = os.path.join(apt_cache_dir, file)
            dest_file = os.path.join(deb_packages_dir, file)
            try:
                shutil.move(src_file, dest_file)
                log_message(f"Moved {src_file} to {dest_file}", download_log_file)
            except Exception as e:
                log_message(f"Failed to move {src_file} to {dest_file}: {str(e)}", download_log_file)

    # Move files from current directory (if any)
    for file in os.listdir('.'):
        if file.endswith(".deb"):
            src_file = os.path.join('.', file)
            dest_file = os.path.join(deb_packages_dir, file)
            try:
                shutil.move(src_file, dest_file)
                log_message(f"Moved {src_file} to {dest_file}", download_log_file)
            except Exception as e:
                log_message(f"Failed to move {src_file} to {dest_file}: {str(e)}", download_log_file)

def clean_apt_cache():
    """Cleans the APT cache to free up space."""
    log_message("Cleaning APT cache...", download_log_file)
    clean_command = subprocess.run(["apt-get", "clean"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if clean_command.returncode == 0:
        log_message("APT cache cleaned.", download_log_file)
    else:
        log_message(f"Failed to clean APT cache: {clean_command.stdout.decode()}", download_log_file)

def download_packages_from_urls(urls_filename):
    """Download deb packages directly from URLs listed in the specified file."""
    if not os.path.exists(urls_filename):
        log_message(f"URLs file {urls_filename} does not exist.", download_log_file)
        return

    with open(urls_filename, 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    for url in urls:
        log_message(f"Attempting to download package from URL: {url}", download_log_file)
        try:
            download_command = ["wget", "-P", deb_packages_dir, url]
            result = subprocess.run(download_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.returncode == 0:
                log_message(f"Successfully downloaded package from {url}", download_log_file)
            else:
                log_message(f"Failed to download package from {url}: {result.stderr}", download_log_file)
        except Exception as e:
            log_message(f"Exception occurred while downloading from {url}: {e}", download_log_file)

def download_packages_from_filenames(filenames_file):
    """Download deb packages by constructing URLs from filenames and a base URL."""
    if not os.path.exists(filenames_file):
        log_message(f"Filenames file {filenames_file} does not exist.", download_log_file)
        return

    if not base_url:
        log_message("No base URL provided. Skipping direct downloads.", download_log_file)
        return

    with open(filenames_file, 'r', encoding='utf-8') as f:
        filenames = [line.strip().strip('\r\n') for line in f if line.strip() and not line.startswith('#')]

    for filename in filenames:
        # Construct the full URL
        full_url = base_url.rstrip('/') + '/' + filename
        log_message(f"Attempting to download package from URL: {full_url}", download_log_file)
        try:
            download_command = ["wget", "-P", deb_packages_dir, full_url]
            result = subprocess.run(download_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.returncode == 0:
                log_message(f"Successfully downloaded package from {full_url}", download_log_file)
            else:
                log_message(f"Failed to download package from {full_url}: {result.stderr}", download_log_file)
        except Exception as e:
            log_message(f"Exception occurred while downloading from {full_url}: {e}", download_log_file)

# Restored `add_repositories` function
def add_repositories():
    """Adds repositories from repos.txt and handles GPG keys securely, supporting custom codenames."""
    if not os.path.exists(repo_list_file):
        log_message(f"Repository list file {repo_list_file} does not exist.", download_log_file)
        return

    with open(repo_list_file, 'r', encoding='utf-8') as f:
        repos = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    try:
        system_codename = subprocess.check_output(["lsb_release", "-cs"], text=True).strip()
    except subprocess.CalledProcessError as e:
        log_message(f"Error obtaining Ubuntu codename: {e}", download_log_file)
        return

    for repo_line in repos:
        try:
            parts = repo_line.split(',', 3)
            repo_name = parts[0]
            repo_entry = parts[1]
            gpg_key_url = parts[2] if len(parts) > 2 else None
            custom_codename = parts[3] if len(parts) > 3 else system_codename

            log_message(f"Adding repository: {repo_name}", download_log_file)

            repo_entry = repo_entry.replace("$(lsb_release -cs)", custom_codename)

            keyring_path = f"/usr/share/keyrings/{repo_name}-archive-keyring.gpg"
            if gpg_key_url:
                log_message(f"Adding GPG key for {repo_name} from {gpg_key_url}", download_log_file)
                subprocess.run(["wget", "-O", keyring_path, gpg_key_url], check=True)
            else:
                log_message(f"No GPG key URL provided for {repo_name}", download_log_file)

            if gpg_key_url:
                repo_entry = insert_signed_by(repo_entry, keyring_path)

            sources_list_file = f"/etc/apt/sources.list.d/{repo_name}.list"
            with open(sources_list_file, 'w', encoding='utf-8') as src_file:
                src_file.write(f"{repo_entry}\n")
        except Exception as e:
            log_message(f"Error adding repository {repo_name}: {e}", download_log_file)

def insert_signed_by(repo_entry, keyring_path):
    """Inserts the signed-by option into the repo_entry correctly."""
    match = re.match(r'^(deb(?:-src)?)(\s+\[.*?\])?(\s+\S+.*)$', repo_entry)
    if match:
        repo_type = match.group(1)
        options = match.group(2)
        rest = match.group(3)

        if options:
            options_content = options.strip()[1:-1].strip()
            options_list = options_content.split()
        else:
            options_list = []

        options_list.append(f"signed-by={keyring_path}")
        options_str = f" [ {' '.join(options_list)} ]"
        return f"{repo_type}{options_str}{rest}"
    else:
        log_message(f"Failed to parse repo entry: {repo_entry}. Skipping signed-by insertion.", download_log_file)
        return repo_entry  # Return unmodified entry without signed-by

def process_deb_file(deb_file, metadata_list, metadata_lock):
    """Process a .deb file: Generate SBOM, Trivy scan, ClamAV scan, Extract metadata."""
    full_deb_path = os.path.join(deb_packages_dir, deb_file)
    generate_sbom_with_trivy(full_deb_path)
    sbom_file = os.path.join(sbom_dir, os.path.basename(full_deb_path).replace(".deb", ".cyclonedx.json"))
    scan_sbom_with_trivy(sbom_file)
    scan_with_clamav(deb_file)
    extract_deb_metadata(full_deb_path, metadata_list, metadata_lock)

def generate_sbom_with_trivy(deb_file):
    """Generate SBOM for a .deb file using Trivy."""
    sbom_file = os.path.join(sbom_dir, os.path.basename(deb_file).replace(".deb", ".cyclonedx.json"))
    trivy_command = ["trivy", "fs", "--format", "cyclonedx", "--output", sbom_file, deb_file]
    log_message(f"Running Trivy command: {' '.join(trivy_command)}", sbom_log_file)

    try:
        result = subprocess.run(trivy_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            log_message(f"SBOM generated successfully at {sbom_file}", sbom_log_file)
        else:
            log_message(f"SBOM generation failed for {deb_file}. Error: {result.stderr}", sbom_log_file)
    except Exception as e:
        log_message(f"Exception during SBOM generation: {e}", sbom_log_file)

def scan_sbom_with_trivy(sbom_file):
    """Scan SBOM for vulnerabilities using Trivy."""
    result_file = os.path.join(trivy_results_dir, os.path.basename(sbom_file).replace('.cyclonedx.json', '-trivy-result.json'))
    trivy_command = ["trivy", "sbom", "--format", "json", "--output", result_file, sbom_file]

    log_message(f"Running Trivy scan on {sbom_file}", trivy_log_file)

    try:
        result = subprocess.run(trivy_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            log_message(f"Trivy scan completed for {sbom_file}", trivy_log_file)
        else:
            log_message(f"Trivy scan failed for {sbom_file}: {result.stderr}", trivy_log_file)
    except Exception as e:
        log_message(f"Exception during Trivy scan: {e}", trivy_log_file)

def scan_with_clamav(deb_file):
    """Scan a .deb file using ClamAV."""
    full_deb_path = os.path.join(deb_packages_dir, deb_file)
    log_message(f"Scanning {full_deb_path} with ClamAV", clamav_log_file)

    clamav_command = ["clamscan", "--infected", "--remove=no", "--recursive", full_deb_path]
    try:
        result = subprocess.run(clamav_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            log_message(f"No threats found in {deb_file}", clamav_log_file)
        elif result.returncode == 1:
            log_message(f"Threats found in {deb_file}:\n{result.stdout}", clamav_log_file)
        else:
            log_message(f"ClamAV scan error for {deb_file}: {result.stderr}", clamav_log_file)
    except Exception as e:
        log_message(f"Exception during ClamAV scan of {deb_file}: {e}", clamav_log_file)

# Metadata extraction and xlsx writing functions
def extract_deb_metadata(deb_file, metadata_list, metadata_lock):
    """Extract metadata from a .deb file and append it to the metadata list, including finding the license type."""
    try:
        log_message(f"Starting metadata extraction from {deb_file}", metadata_log_file)

        # Open the .deb file
        deb = debian.debfile.DebFile(deb_file)
        log_message(f"Opened deb file {deb_file} successfully.", metadata_log_file)

        control = deb.debcontrol()  # Returns a Deb822 object

        package_name = control.get('Package', 'N/A')
        version = control.get('Version', 'N/A')
        homepage_url = control.get('Homepage', 'N/A')  # Get the homepage URL if it exists

        # Initialize license_content
        license_type = ''  # Default if no license type is found

        # Try to read the copyright file from the data archive
        try:
            # Construct the path to the copyright file
            copyright_path = f'usr/share/doc/{package_name}/copyright'

            # Attempt to read the copyright file
            license_file = deb.data.get_file(copyright_path)
            license_content = license_file.read().decode('utf-8', errors='replace')

            # Attempt to extract license type
            # This logic assumes the license type will be explicitly mentioned in the file
            # We check for common licenses like BSD, GPL, MIT, etc.
            license_patterns = [
                "BSD", "GPL", "MIT", "Apache", "LGPL", "MPL", "CC0", "Artistic", "Public Domain"
            ]
            for license_name in license_patterns:
                if license_name in license_content:
                    license_type = license_name
                    log_message(f"{license_name} license found for {package_name}", metadata_log_file)
                    break

            if license_type == 'N/A':
                log_message(f"No common license type found for {package_name}", metadata_log_file)

        except Exception as e:
            log_message(f"Could not read license file for {package_name}: {e}", metadata_log_file, level="WARNING")
            license_type = ''

        # Prepare metadata to be appended
        metadata = {
            'Name': package_name,
            'Version': version,
            'License Type': license_type,
            'URL': homepage_url
        }

        # Append metadata to the shared list
        with metadata_lock:
            metadata_list.append(metadata)

        log_message(f"Extracted metadata from {deb_file}", metadata_log_file)

    except Exception as e:
        log_message(f"Exception during metadata extraction from {deb_file}: {e}", metadata_log_file)


def write_metadata_to_xlsx(metadata_list):
    """Write the collected metadata to an xlsx file."""
    xlsx_file = os.path.join(metadata_dir, "deb_metadata.xlsx")

    try:
        wb = Workbook()
        ws = wb.active
        ws.title = "Debian Packages Metadata"

        # Write headers
        headers = ['Name', 'Version', 'License Type', 'URL']
        ws.append(headers)

        # Set column widths for better readability
        ws.column_dimensions['A'].width = 30  # Name
        ws.column_dimensions['B'].width = 20  # Version
        ws.column_dimensions['C'].width = 20  # License Type
        ws.column_dimensions['D'].width = 50  # URL

        # Write data rows
        for metadata in metadata_list:
            row = [metadata.get(field, 'N/A') for field in headers]
            ws.append(row)

        wb.save(xlsx_file)
        log_message(f"Metadata written to {xlsx_file}", metadata_log_file)
    except Exception as e:
        log_message(f"Exception during writing metadata to xlsx file: {e}", metadata_log_file)


# Main script logic
if __name__ == "__main__":
    # Log the selected Ubuntu version for reference
    log_message(f"Selected Ubuntu version: {ubuntu_version}", download_log_file)

    # Bypass repository logic if download_mode is "URL" or "FILENAME"
    if download_mode == "URL":
        download_packages_from_urls(download_file)
    elif download_mode == "FILENAME":
        download_packages_from_filenames(download_file)
    else:
        add_repositories()
        update_package_lists()
        download_all_packages()

    # Update ClamAV definitions
    update_clamav_definitions()

    # Process downloaded .deb files (SBOM generation, Trivy scan, ClamAV scan, Metadata extraction)
    deb_files = [f for f in os.listdir(deb_packages_dir) if f.endswith(".deb")]

    # Shared metadata list and lock
    metadata_list = []
    metadata_lock = threading.Lock()

    with ThreadPoolExecutor(max_workers=scan_threads) as executor:
        tasks = [executor.submit(process_deb_file, deb_file, metadata_list, metadata_lock) for deb_file in deb_files]

        for task in as_completed(tasks):
            task.result()

    # After processing all deb files, write metadata to xlsx
    write_metadata_to_xlsx(metadata_list)

    log_message("Processing completed. Check the logs for details.", download_log_file)
