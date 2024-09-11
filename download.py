import os
import subprocess
import shutil
import json
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

output_dir = "./deb_packages"
sbom_dir = "./sbom_results"
trivy_results_dir = "./trivy_results"
log_file = "verification_log.txt"
package_list_file = "packages.txt"
repo_list_file = "repos.txt"
downloaded_packages = set()
max_threads = 5  # Define the maximum number of threads

os.makedirs(output_dir, exist_ok=True)
os.makedirs(sbom_dir, exist_ok=True)
os.makedirs(trivy_results_dir, exist_ok=True)

with open(log_file, 'w') as log:
    log.write("Starting package download and verification\n")
    log.write(f"Date: {subprocess.getoutput('date')}\n")
    log.write("========================\n")

def log_message(message):
    with open(log_file, 'a') as log:
        log.write(message + "\n")
    print(message)

def move_deb_files():
    """Move downloaded .deb files from both the apt cache and the working directory to the output directory."""
    apt_cache_dir = "/var/cache/apt/archives"
    for file in os.listdir(apt_cache_dir):
        if file.endswith(".deb"):
            src_file = os.path.join(apt_cache_dir, file)
            dest_file = os.path.join(output_dir, file)
            log_message(f"Attempting to move {file} to {output_dir} from {apt_cache_dir}")
            if os.path.exists(dest_file):
                os.remove(dest_file)  # Remove the existing file before moving
            shutil.move(src_file, output_dir)
            log_message(f"Moved {file} to {output_dir} from APT cache")

    # Move any .deb files from the current working directory (root of the project)
    for file in os.listdir('.'):
        if file.endswith(".deb"):
            src_file = os.path.join('.', file)
            dest_file = os.path.join(output_dir, file)
            log_message(f"Attempting to move {file} to {output_dir} from the current directory")
            if os.path.exists(dest_file):
                os.remove(dest_file)  # Remove the existing file before moving
            shutil.move(src_file, output_dir)
            log_message(f"Moved {file} to {output_dir} from the current directory")

def clean_apt_cache():
    """Clean up the APT cache after downloading the files."""
    log_message("Cleaning APT cache...")
    clean_command = subprocess.run(["sudo", "apt-get", "clean"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if clean_command.returncode == 0:
        log_message("APT cache cleaned.")
    else:
        log_message(f"Failed to clean APT cache: {clean_command.stdout.decode()}")

def change_ownership_of_files():
    """Change the ownership of files in the output directories to the current user."""
    log_message("Changing ownership of all files in output directories to current user...")
    subprocess.run(["sudo", "chown", "-R", f"{os.getlogin()}:{os.getlogin()}", output_dir, sbom_dir, trivy_results_dir, log_file], check=True)
    log_message("Ownership changed.")

def read_repos_from_file(file_path):
    repos = {}
    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            if not line or ',' not in line:  # Skip empty lines or lines without a comma
                log_message(f"Skipping invalid line in repos file: '{line}'")
                continue
            repo_name, repo_url = line.split(',', 1)  # Split only on the first comma
            repos[repo_name] = repo_url
    return repos

def read_packages_from_file(file_path):
    packages = []
    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            if not line or ',' not in line:  
                log_message(f"Skipping invalid line in packages file: '{line}'")
                continue
            repo_name, package_path = line.split(',', 1)
            packages.append((repo_name, package_path))
    return packages

def download_package_via_apt(package):
    log_message(f"******** Downloading {package} via APT ********")

    pkg_name = package.split('=')[0]

    # Use apt-rdepends to get the list of dependencies
    result = subprocess.run(["apt-rdepends", pkg_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        log_message(f"Failed to get dependencies for {package}: {result.stderr.decode()}")
        return

    # Parse the dependencies
    dependencies = set(line.decode('utf-8').strip() for line in result.stdout.splitlines()
                       if line and not line.startswith(b' '))

    # Download each dependency and the main package
    for dep in dependencies:
        if dep not in downloaded_packages:
            log_message(f"Downloading {dep}...")
            download_success = subprocess.run(["sudo", "apt-get", "download", dep], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            if download_success.returncode == 0:
                downloaded_packages.add(dep)
                log_message(f"Downloaded {dep}")
            else:
                log_message(f"Failed to download {dep}. Skipping.")
                log_message(download_success.stdout.decode())
        else:
            log_message(f"{dep} is already downloaded")

    # Move all .deb files to the specified output directory
    move_deb_files()

    log_message("******************************")

def download_package_via_url(repo_url, package_path):
    log_message(f"******** Downloading {package_path} from {repo_url} ********")

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
        log_message(f"Downloaded: {file_name}")
        move_deb_files()

    except requests.exceptions.RequestException as e:
        log_message(f"Failed to download {package_path} from {repo_url}: {e}")

def generate_sbom_with_trivy(deb_file):
    sbom_file = os.path.join(sbom_dir, os.path.basename(deb_file).replace(".deb", ".cyclonedx.json"))
    log_message(f"Generating SBOM for {deb_file} with Trivy...")
    trivy_command = f"trivy fs --format cyclonedx --output {sbom_file} {deb_file}"
    result = subprocess.run(trivy_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        log_message(f"SBOM generated at {sbom_file}")
    else:
        log_message(f"Failed to generate SBOM for {deb_file}: {result.stderr.decode()}")

def scan_sboms_in_directory():
    log_message(f"Scanning all SBOMs in {sbom_dir} with Trivy...")
    for sbom_file in os.listdir(sbom_dir):
        if sbom_file.endswith(".cyclonedx.json"):
            full_sbom_path = os.path.join(sbom_dir, sbom_file)
            log_message(f"Scanning SBOM {full_sbom_path} with Trivy...")
            result_file = os.path.join(trivy_results_dir, sbom_file.replace('.cyclonedx.json', '-trivy-result.json'))
            trivy_command = f"trivy sbom {full_sbom_path} --format json --output {result_file}"
            result = subprocess.run(trivy_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            if result.returncode == 0:
                log_message(f"Trivy scan completed for {full_sbom_path}")
                with open(result_file, 'r') as rf:
                    scan_results = json.load(rf)
                    vulnerabilities = scan_results.get('Results', [])

                    if vulnerabilities:
                        log_message(f"Vulnerabilities found in {full_sbom_path}:")
                        log_message(json.dumps(vulnerabilities, indent=2))
                    else:
                        log_message(f"No vulnerabilities found in {full_sbom_path}.")
            else:
                log_message(f"Trivy scan failed for {full_sbom_path}: {result.stderr.decode()}")

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

    # Download APT packages sequentially without threads
    for package in apt_packages:
        download_package_via_apt(package)

    # Download other packages with the original max_threads
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        tasks = []
        for repo_or_flag, package_or_path in other_packages:
            if repo_or_flag in repos:
                tasks.append(executor.submit(download_package_via_url, repos[repo_or_flag], package_or_path))
            else:
                log_message(f"Unknown repository or flag '{repo_or_flag}' for package '{package_or_path}'.")
        
        for task in as_completed(tasks):
            task.result()

    # Clean up the APT cache after downloading
    clean_apt_cache()

if __name__ == "__main__":
    download_all_packages()

    for deb_file in os.listdir(output_dir):
        if deb_file.endswith(".deb"):
            full_deb_path = os.path.join(output_dir, deb_file)
            generate_sbom_with_trivy(full_deb_path)

    scan_sboms_in_directory()

    # Change ownership of all files to the current user after everything is done
    change_ownership_of_files()

    log_message("Verification completed. Check the log for details.")

