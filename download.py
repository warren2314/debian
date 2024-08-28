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
package_list_file = "warren_cleaned1.txt"
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
    for file in os.listdir('.'):
        if file.endswith(".deb"):
            dest_file = os.path.join(output_dir, file)
            if os.path.exists(dest_file):
                os.remove(dest_file)  # Remove the existing file before moving
            shutil.move(file, output_dir)
            log_message(f"Moved {file} to {output_dir}")

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
            if not line or ',' not in line:  # Skip empty lines or lines without a comma
                log_message(f"Skipping invalid line in packages file: '{line}'")
                continue
            repo_name, package_path = line.split(',', 1)
            packages.append((repo_name, package_path))
    return packages

def download_terraform(repo_url, version):
    log_message(f"******** Downloading Terraform version {version} ********")

    try:
        # Construct the correct URL for the specified version
        url = f"{repo_url}{version}/terraform_{version}_linux_amd64.zip"
        response = requests.get(url)
        response.raise_for_status()  # Ensure we notice bad responses

        # Save the file
        file_name = os.path.join(output_dir, f"terraform_{version}_linux_amd64.zip")
        with open(file_name, 'wb') as file:
            file.write(response.content)
        log_message(f"Downloaded: {file_name}")

    except requests.exceptions.RequestException as e:
        log_message(f"Failed to download Terraform version {version}: {e}")

def setup_powerdns_repository():
    log_message("Setting up PowerDNS repository...")

    try:
        # Step 1: Add the PowerDNS repository key
        subprocess.run(
            "sudo install -d /etc/apt/keyrings && curl https://repo.powerdns.com/FD380FBB-pub.asc | sudo tee /etc/apt/keyrings/auth-45-pub.asc",
            shell=True, check=True
        )
        
        # Step 2: Update APT package list
        subprocess.run("sudo apt-get update", shell=True, check=True)
        log_message("PowerDNS repository setup complete.")
    
    except subprocess.CalledProcessError as e:
        log_message(f"Failed to set up PowerDNS repository: {e}")

def download_package_via_apt(package):
    log_message(f"******** Downloading {package} via APT ********")

    pkg_name = package.split('=')[0]

    if pkg_name == 'pdns-server':
        # Run PowerDNS repository setup before installation
        setup_powerdns_repository()

    result = subprocess.run(["apt-rdepends", pkg_name], stdout=subprocess.PIPE)
    dependencies = set(line.decode('utf-8').strip() for line in result.stdout.splitlines()
                       if line and not line.startswith(b' '))

    if package not in downloaded_packages:
        download_success = subprocess.run(["sudo", "apt-get", "install", "-y", package], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if download_success.returncode == 0:
            move_deb_files()  # Move files after successful download
            downloaded_packages.add(package)
            log_message(f"Downloaded {package}")
        else:
            log_message(f"Failed to download {package}. Skipping.")
            log_message(download_success.stdout.decode())
    else:
        log_message(f"{package} is already downloaded")

    for dep in dependencies:
        if dep not in downloaded_packages:
            log_message(f"Downloading {dep}...")
            download_success = subprocess.run(["sudo", "apt-get", "install", "-y", dep], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            if download_success.returncode == 0:
                move_deb_files()  # Move files after successful download
                downloaded_packages.add(dep)
                log_message(f"Downloaded {dep}")
            else:
                log_message(f"Failed to download {dep}. Skipping.")
                log_message(download_success.stdout.decode())
        else:
            log_message(f"{dep} is already downloaded")

    log_message("******************************")

def download_package_via_url(repo_url, package_path):
    log_message(f"******** Downloading {package_path} from {repo_url} ********")

    try:
        # Ensure the URL is properly constructed with a '/'
        if not repo_url.endswith('/'):
            repo_url += '/'
        if package_path.startswith('/'):
            package_path = package_path[1:]
        
        # Construct the full URL
        url = f"{repo_url}{package_path}"
        response = requests.get(url)
        response.raise_for_status()  # Ensure we notice bad responses

        # Save the file
        file_name = os.path.join(output_dir, package_path.split('/')[-1])
        with open(file_name, 'wb') as file:
            file.write(response.content)
        log_message(f"Downloaded: {file_name}")
        move_deb_files()  # Move files after successful download

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
                
                # Check if vulnerabilities were found
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
    
    tasks = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        for repo_or_flag, package_or_path in packages:
            if repo_or_flag == 'apt':
                # We will run APT downloads in a separate thread
                tasks.append(executor.submit(download_package_via_apt, package_or_path))
            elif repo_or_flag == 'terraform':
                # Terraform download
                tasks.append(executor.submit(download_terraform, repos[repo_or_flag], package_or_path))
            elif repo_or_flag in repos:
                # URL-based download
                tasks.append(executor.submit(download_package_via_url, repos[repo_or_flag], package_or_path))
            else:
                log_message(f"Unknown repository or flag '{repo_or_flag}' for package '{package_or_path}'.")

        for task in as_completed(tasks):
            task.result()  # To raise any exceptions that occurred during download

if __name__ == "__main__":
    download_all_packages()

    for deb_file in os.listdir(output_dir):
        if deb_file.endswith(".deb"):
            full_deb_path = os.path.join(output_dir, deb_file)
            generate_sbom_with_trivy(full_deb_path)

    scan_sboms_in_directory()
    log_message("Verification completed. Check the log for details.")

