# Use an argument for the Ubuntu version
ARG UBUNTU_VERSION="22.04"

# Set the base image according to the Ubuntu version
FROM ubuntu:${UBUNTU_VERSION}

# Install necessary packages
RUN apt-get update -y && apt-get install -y \
    apt-utils \
    apt-transport-https \
    ca-certificates \
    curl \
    wget \
    gnupg \
    lsb-release \
    software-properties-common \
    python3-venv \
    python3-pip \
    zstd \
    apt-rdepends

# Setup working directory
WORKDIR /usr/src/app

# Copy necessary files including filenames.txt
COPY main.py generate_llm_report.py packages.txt repos.txt requirements.txt filenames.txt urls.txt ./

# Install Python virtual environment and dependencies
RUN python3 -m venv venv && \
    ./venv/bin/pip install --upgrade pip && \
    ./venv/bin/pip install -r requirements.txt

# Install ClamAV and Trivy
RUN apt-get update && apt-get install -y clamav clamav-daemon && \
    sed -i 's/^Example/#Example/' /etc/clamav/freshclam.conf && \
    freshclam

# Install Trivy with dynamic version
ARG TRIVY_VERSION="0.55.1"
RUN wget https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.deb && \
    dpkg -i trivy_${TRIVY_VERSION}_Linux-64bit.deb && \
    rm trivy_${TRIVY_VERSION}_Linux-64bit.deb

# Ensure output directories exist
RUN mkdir -p /mnt/output/deb_packages /mnt/output/sbom_results /mnt/output/trivy_results /mnt/output/logs

# Set entrypoint to use Python virtual environment and execute both scripts
ENTRYPOINT ["./venv/bin/python", "-u", "./main.py", "&&", "./venv/bin/python", "./generate_llm_report.py", "/mnt/output/sbom_results", "/mnt/output/trivy_results", "/mnt/output/final_report.pdf"]
