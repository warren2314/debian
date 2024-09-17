import os
import subprocess
import shutil
import datetime

output_dir = "/mnt/output"
deb_packages_dir = os.path.join(output_dir, "deb_packages")
sbom_dir = os.path.join(output_dir, "sbom_results")
trivy_results_dir = os.path.join(output_dir, "trivy_results")
logs_dir = os.path.join(output_dir, "logs")
download_log_file = os.path.join(logs_dir, "download_log.txt")
sbom_log_file = os.path.join(logs_dir, "sbom_log.txt")
trivy_log_file = os.path.join(logs_dir, "trivy_log.txt")
clamav_log_file = os.path.join(logs_dir, "clamav_log.txt")
package_list_file = "packages.txt"
repo_list_file = "repos.txt"
max_threads = 5
scan_threads = 5


# Ensure all necessary directories exist
def ensure_directories_exist():
    """Ensure all necessary directories exist."""
    dirs = [deb_packages_dir, sbom_dir, trivy_results_dir, logs_dir]

    for directory in dirs:
        if not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
            os.chmod(directory, 0o777)  # Ensure directories are writable


ensure_directories_exist()


def log_message(message, log_file):
    """Logs messages to the appropriate log file with timestamps."""
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(log_file, 'a') as log:
        log.write(f"{timestamp} - {message}\n")
    print(f"{timestamp} - {message}")


def update_package_lists():
    """Updates the package lists."""
    log_message("Updating package lists...", download_log_file)
    update_command = subprocess.run(["apt-get", "update"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if update_command.returncode == 0:
        log_message("Package lists updated.", download_log_file)
    else:
        log_message(f"Failed to update package lists: {update_command.stdout.decode()}", download_log_file)


def add_repositories():
    """Adds repositories from repos.txt and handles GPG keys."""
    if not os.path.exists(repo_list_file):
        log_message(f"Repository list file {repo_list_file} does not exist.", download_log_file)
        return

    with open(repo_list_file, 'r') as f:
        repos = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    for repo_line in repos:
        try:
            # Expected format: repo_name,repo_url,gpg_key_url
            parts = repo_line.split(',')
            repo_name = parts[0]
            repo_url = parts[1]
            gpg_key_url = parts[2] if len(parts) > 2 else None

            log_message(f"Adding repository: {repo_name} ({repo_url})", download_log_file)

            # Add GPG key if provided
            if gpg_key_url:
                log_message(f"Adding GPG key for {repo_name} from {gpg_key_url}", download_log_file)
                subprocess.run(["wget", "-O", f"/usr/share/keyrings/{repo_name}-archive-keyring.gpg", gpg_key_url],
                               check=True)
                key_option = f"[signed-by=/usr/share/keyrings/{repo_name}-archive-keyring.gpg]"
            else:
                key_option = ""

            # Create a new sources list file for the repo
            sources_list_file = f"/etc/apt/sources.list.d/{repo_name}.list"
            with open(sources_list_file, 'w') as src_file:
                src_file.write(f"deb {key_option} {repo_url} $(lsb_release -cs) main\n")
        except Exception as e:
            log_message(f"Error adding repository {repo_line}: {e}", download_log_file)


def download_all_packages():
    """Download all packages listed in the package list file."""
    if not os.path.exists(package_list_file):
        log_message(f"Package list file {package_list_file} does not exist.", download_log_file)
        return

    packages = []

    with open(package_list_file, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                # Split by commas, first element is repo name, rest are package names
                parts = line.split(',')
                if len(parts) >= 2:
                    repo_name = parts[0]
                    package_names = parts[1:]
                    packages.extend(package_names)
                else:
                    packages.append(parts[0])  # If no repo specified, just take the package name

    for package in packages:
        log_message(f"Attempting to download package: {package}", download_log_file)
        download_command = ["apt-get", "download", package]
        try:
            result = subprocess.run(download_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.returncode == 0:
                log_message(f"Successfully downloaded {package}", download_log_file)
            else:
                log_message(f"Failed to download {package}: {result.stderr}", download_log_file)
        except Exception as e:
            log_message(f"Exception occurred while downloading {package}: {e}", download_log_file)

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
    result_file = os.path.join(trivy_results_dir,
                               os.path.basename(sbom_file).replace('.cyclonedx.json', '-trivy-result.json'))
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


def process_deb_file(deb_file):
    """Process a .deb file: Generate SBOM, Trivy scan, ClamAV scan."""
    full_deb_path = os.path.join(deb_packages_dir, deb_file)

    # 1. Generate SBOM
    generate_sbom_with_trivy(full_deb_path)

    # 2. Trivy scan SBOM
    sbom_file = os.path.join(sbom_dir, os.path.basename(full_deb_path).replace(".deb", ".cyclonedx.json"))
    scan_sbom_with_trivy(sbom_file)

    # 3. Scan with ClamAV
    scan_with_clamav(deb_file)


if __name__ == "__main__":
    add_repositories()
    update_package_lists()
    download_all_packages()

    update_clamav_definitions()

    from concurrent.futures import ThreadPoolExecutor, as_completed

    deb_files = [f for f in os.listdir(deb_packages_dir) if f.endswith(".deb")]
    with ThreadPoolExecutor(max_workers=scan_threads) as executor:
        tasks = [executor.submit(process_deb_file, deb_file) for deb_file in deb_files]

        for task in as_completed(tasks):
            task.result()

    log_message("Processing completed. Check the logs for details.", download_log_file)
