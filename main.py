import os
import subprocess
import shutil
import json
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

output_dir = "./deb_packages"
sbom_dir = "./sbom_results"
trivy_results_dir = "./trivy_results"
logs_dir = "./logs"
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
os.makedirs(output_dir, exist_ok=True)
os.makedirs(sbom_dir, exist_ok=True)
os.makedirs(trivy_results_dir, exist_ok=True)
os.makedirs(logs_dir, exist_ok=True)


def log_message(message, log_file):
    """Logs messages to the appropriate log file."""
    with open(log_file, 'a') as log:
        log.write(message + "\n")
    print(message)


def move_deb_files():
    apt_cache_dir = "/var/cache/apt/archives"
    for file in os.listdir(apt_cache_dir):
        if file.endswith(".deb"):
            src_file = os.path.join(apt_cache_dir, file)
            dest_file = os.path.join(output_dir, file)
            log_message(f"Attempting to move {file} to {output_dir} from {apt_cache_dir}", download_log_file)
            if os.path.exists(dest_file):
                os.remove(dest_file)
            shutil.move(src_file, output_dir)
            log_message(f"Moved {file} to {output_dir} from APT cache", download_log_file)

    for file in os.listdir('.'):
        if file.endswith(".deb"):
            src_file = os.path.join('.', file)
            dest_file = os.path.join(output_dir, file)
            log_message(f"Attempting to move {file} to {output_dir} from the current directory", download_log_file)
            if os.path.exists(dest_file):
                os.remove(dest_file)
            shutil.move(src_file, output_dir)
            log_message(f"Moved {file} to {output_dir} from the current directory", download_log_file)


def clean_apt_cache():
    log_message("Cleaning APT cache...", download_log_file)
    clean_command = subprocess.run(["sudo", "apt-get", "clean"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if clean_command.returncode == 0:
        log_message("APT cache cleaned.", download_log_file)
    else:
        log_message(f"Failed to clean APT cache: {clean_command.stdout.decode()}", download_log_file)


def change_ownership_of_files():
    """Change the ownership of files in the output directories and logs to the current user."""
    log_message("Changing ownership of all files in output and logs directories to current user...", download_log_file)
    subprocess.run(
        ["sudo", "chown", "-R", f"{os.getlogin()}:{os.getlogin()}", output_dir, sbom_dir, trivy_results_dir, logs_dir],
        check=True)
    log_message("Ownership changed.", download_log_file)


def read_repos_from_file(file_path):
    repos = {}
    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            if not line or ',' not in line:
                log_message(f"Skipping invalid line in repos file: '{line}'", download_log_file)
                continue
            repo_name, repo_url = line.split(',', 1)
            repos[repo_name] = repo_url
    return repos


def read_packages_from_file(file_path):
    packages = []
    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            if not line or ',' not in line:
                log_message(f"Skipping invalid line in packages file: '{line}'", download_log_file)
                continue
            repo_name, package_path = line.split(',', 1)
            packages.append((repo_name, package_path))
    return packages


def download_package_via_apt(package):
    log_message(f"******** Downloading {package} via APT ********", download_log_file)

    pkg_name = package.split('=')[0]
    result = subprocess.run(["apt-rdepends", pkg_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        log_message(f"Failed to get dependencies for {package}: {result.stderr.decode()}", download_log_file)
        return

    dependencies = set(line.decode('utf-8').strip() for line in result.stdout.splitlines()
                       if line and not line.startswith(b' '))

    for dep in dependencies:
        if dep not in downloaded_packages:
            log_message(f"Downloading {dep}...", download_log_file)
            download_success = subprocess.run(["sudo", "apt-get", "download", dep], stdout=subprocess.PIPE,
                                              stderr=subprocess.STDOUT)
            if download_success.returncode == 0:
                downloaded_packages.add(dep)
                log_message(f"Downloaded {dep}", download_log_file)
            else:
                log_message(f"Failed to download {dep}. Skipping.", download_log_file)
                log_message(download_success.stdout.decode(), download_log_file)
        else:
            log_message(f"{dep} is already downloaded", download_log_file)

    move_deb_files()
    log_message("******************************", download_log_file)


def download_package_via_url(repo_url, package_path):
    log_message(f"******** Downloading {package_path} from {repo_url} ********", download_log_file)
    try:
        if not repo_url.endswith('/'):
            repo_url += '/'
        if package_path.startswith('/'):
            package_path = package_path[1:]

        url = f"{repo_url}{package_path}"
        response = requests.get(url)
        response.raise_for_status()

        file_name = os.path.join(output_dir, package_path.split('/')[-1])
        with open(file_name, 'wb') as file:
            file.write(response.content)
        log_message(f"Downloaded: {file_name}", download_log_file)
        move_deb_files()

    except requests.exceptions.RequestException as e:
        log_message(f"Failed to download {package_path} from {repo_url}: {e}", download_log_file)


def generate_sbom_with_trivy(deb_file):
    sbom_file = os.path.join(sbom_dir, os.path.basename(deb_file).replace(".deb", ".cyclonedx.json"))
    log_message(f"Generating SBOM for {deb_file} with Trivy...", sbom_log_file)
    trivy_command = f"trivy fs --format cyclonedx --output {sbom_file} {deb_file}"
    result = subprocess.run(trivy_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        log_message(f"SBOM generated at {sbom_file}", sbom_log_file)
    else:
        log_message(f"Failed to generate SBOM for {deb_file}: {result.stderr.decode()}", sbom_log_file)


def scan_sbom_with_trivy(sbom_file):
    log_message(f"Scanning SBOM {sbom_file} with Trivy...", trivy_log_file)
    result_file = os.path.join(trivy_results_dir,
                               os.path.basename(sbom_file).replace('.cyclonedx.json', '-trivy-result.json'))
    trivy_command = f"trivy sbom {sbom_file} --format json --output {result_file}"
    result = subprocess.run(trivy_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        log_message(f"Trivy scan completed for {sbom_file}", trivy_log_file)
    else:
        log_message(f"Trivy scan failed for {sbom_file}: {result.stderr.decode()}", trivy_log_file)


def clamav_scan(deb_file):
    log_message(f"Running ClamAV scan on {deb_file}...", clamav_log_file)
    clamscan_command = f"clamscan {deb_file}"
    result = subprocess.run(clamscan_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        log_message(f"ClamAV scan completed for {deb_file}:\n{result.stdout.decode()}", clamav_log_file)
    else:
        log_message(f"ClamAV scan failed for {deb_file}: {result.stderr.decode()}", clamav_log_file)


def process_deb_file(deb_file):
    """Process a .deb file: Generate SBOM, Trivy scan, then ClamAV scan."""
    full_deb_path = os.path.join(output_dir, deb_file)

    # 1. Generate SBOM
    generate_sbom_with_trivy(full_deb_path)

    # 2. Trivy scan SBOM
    sbom_file = os.path.join(sbom_dir, os.path.basename(full_deb_path).replace(".deb", ".cyclonedx.json"))
    scan_sbom_with_trivy(sbom_file)

    # 3. ClamAV scan the .deb file
    clamav_scan(full_deb_path)


def download_all_packages():
    repos = read_repos_from_file(repo_list_file)  # Load repos
    packages = read_packages_from_file(package_list_file)  # Load packages

    apt_packages = []
    other_packages = []

    for repo_or_flag, package_or_path in packages:
        if repo_or_flag == 'apt':
            apt_packages.append(package_or_path)
        else:
            other_packages.append((repo_or_flag, package_or_path))

    for package in apt_packages:
        download_package_via_apt(package)

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        tasks = []
        for repo_or_flag, package_or_path in other_packages:
            if repo_or_flag in repos:
                tasks.append(executor.submit(download_package_via_url, repos[repo_or_flag], package_or_path))
            else:
                log_message(f"Unknown repository or flag '{repo_or_flag}' for package '{package_or_path}'.",
                            download_log_file)

        for task in as_completed(tasks):
            task.result()

    clean_apt_cache()


if __name__ == "__main__":
    # Step 1: Download all packages
    download_all_packages()

    # Step 2: Process all .deb files in parallel (SBOM, Trivy, ClamAV)
    deb_files = [f for f in os.listdir(output_dir) if f.endswith(".deb")]
    with ThreadPoolExecutor(max_workers=scan_threads) as executor:
        tasks = [executor.submit(process_deb_file, deb_file) for deb_file in deb_files]

        for task in as_completed(tasks):
            task.result()

    # Step 3: Change ownership of all files including logs
    change_ownership_of_files()

    log_message("Verification completed. Check the logs for details.", download_log_file)