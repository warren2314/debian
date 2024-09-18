# Use an argument for Ubuntu version
ARG UBUNTU_VERSION=24.04
FROM ubuntu:${UBUNTU_VERSION}

# Set non-interactive mode for APT
ENV DEBIAN_FRONTEND=noninteractive

# Install necessary tools including GnuPG and lsb-release
RUN apt-get update && apt-get install -y \
    apt-utils \
    apt-transport-https \
    ca-certificates \
    curl \
    wget \
    gnupg \
    lsb-release \
    software-properties-common \
    python3 \
    python3-pip \
    python3-venv \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create a directory for the app
RUN mkdir -p /usr/src/app

# Set working directory
WORKDIR /usr/src/app

# Copy requirements.txt and install Python dependencies
COPY requirements.txt ./
RUN python3 -m venv venv && \
    ./venv/bin/pip install --upgrade pip && \
    ./venv/bin/pip install -r requirements.txt

# Copy the application code
COPY main.py packages.txt repos.txt ./

# Ensure the script is executable
RUN chmod +x main.py

# Install ClamAV
RUN apt-get update && apt-get install -y clamav clamav-daemon && \
    sed -i 's/^Example/#Example/' /etc/clamav/freshclam.conf && \
    freshclam

# Install Trivy
RUN wget https://github.com/aquasecurity/trivy/releases/download/v0.55.1/trivy_0.55.1_Linux-64bit.deb && \
    dpkg -i trivy_0.55.1_Linux-64bit.deb && \
    rm trivy_0.55.1_Linux-64bit.deb && \
    trivy image --download-db-only

# Create output directories
RUN mkdir -p /mnt/output/deb_packages /mnt/output/sbom_results /mnt/output/trivy_results /mnt/output/logs

# Set the command to execute your script
CMD ["./venv/bin/python", "main.py"]
