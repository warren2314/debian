import os
import subprocess
import shutil
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

output_dir = "/mnt/output/deb_packages"
sbom_dir = "/mnt/output/sbom_results"
trivy_results_dir = "/mnt/output/trivy_results"
logs_dir = "/mnt/output/logs"
download_log_file = os.path.join(logs_dir, "download_log.txt")
sbom_log_file = os.path.join(logs_dir, "sbom_log.txt")
trivy_log_file = os.path.join(logs_dir, "trivy_log.txt")
clamav_log_file = os.path.join(logs_dir, "clamav_log.txt")
package_list_file = "packages.txt"
repo_list_file = "repos.txt"
downloaded_packages = set()
max_threads = 5
scan_threads = 5


# Ensure all necessary directories exist
def ensure_directories_exist():
    """Ensure all necessary directories exist."""
    dirs = [output_dir, sbom_dir, trivy_results_dir, logs_dir]

    for directory in dirs:
        if not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
            os.chmod(directory, 0o777)  # Ensure directories are writable


ensure_directories_exist()


def log_message(message, log_file):
    """Logs messages to the appropriate log file."""
    with open(log_file, 'a') as log:
        log.write(message + "\n")
    print(message)


def move_deb_files():
    """Moves .deb files from APT cache and current directory to the output directory."""
    apt_cache_dir = "/var/cache/apt/archives"

    # Ensure the deb_packages directory exists
    ensure_directories_exist()

    # Log files in the APT cache directory
    log_message(f"Files in {apt_cache_dir}: {os.listdir(apt_cache_dir)}", download_log_file)

    # Move files from APT cache directory
    for file in os.listdir(apt_cache_dir):
        if file.endswith(".deb"):
            src_file = os.path.join(apt_cache_dir, file)
            dest_file = os.path.join(output_dir, file)
            log_message(f"Attempting to move {src_file} to {dest_file}", download_log_file)
            try:
                shutil.move(src_file, dest_file)
                log_message(f"Successfully moved {src_file} to {dest_file}", download_log_file)
            except Exception as e:
                log_message(f"Failed to move {src_file} to {dest_file}: {str(e)}", download_log_file)

    # Move files from current directory (if any)
    for file in os.listdir('.'):
        if file.endswith(".deb"):
            src_file = os.path.join('.', file)
            dest_file = os.path.join(output_dir, file)
            log_message(f"Attempting to move {src_file} to {dest_file}", download_log_file)
            try:
                shutil.move(src_file, dest_file)
                log_message(f"Successfully moved {src_file} to {dest_file}", download_log_file)
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


def process_deb_file(deb_file):
    """Process a .deb file: Generate SBOM, Trivy scan."""
    full_deb_path = os.path.join(output_dir, deb_file)

    # 1. Generate SBOM
    generate_sbom_with_trivy(full_deb_path)

    # 2. Trivy scan SBOM
    sbom_file = os.path.join(sbom_dir, os.path.basename(full_deb_path).replace(".deb", ".cyclonedx.json"))
    scan_sbom_with_trivy(sbom_file)


def download_all_packages():
    """Download all packages listed in the package list file."""
    # Download logic would go here
    move_deb_files()
    clean_apt_cache()


if __name__ == "__main__":
    download_all_packages()

    deb_files = [f for f in os.listdir(output_dir) if f.endswith(".deb")]
    with ThreadPoolExecutor(max_workers=scan_threads) as executor:
        tasks = [executor.submit(process_deb_file, deb_file) for deb_file in deb_files]

        for task in as_completed(tasks):
            task.result()

    log_message("Verification completed. Check the logs for details.", download_log_file)
