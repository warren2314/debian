# Use an argument for Ubuntu version
ARG UBUNTU_VERSION=22.04
FROM ubuntu:${UBUNTU_VERSION}

# Install necessary tools including ClamAV
RUN apt-get update && apt-get install -y \
    apt-utils \
    apt-rdepends \
    curl \
    ca-certificates \
    wget \
    gnupg \
    software-properties-common \
    lsb-release \
    clamav \
    clamav-daemon \
    python3 \
    python3-pip \
    python3-venv \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Fix ClamAV configuration for freshclam
RUN sed -i 's/^Example/#Example/' /etc/clamav/freshclam.conf

# Fix ClamAV permissions
RUN mkdir -p /var/lib/clamav && \
    chown -R clamav:clamav /var/lib/clamav

# Install Trivy from official sources
RUN wget https://github.com/aquasecurity/trivy/releases/download/v0.55.1/trivy_0.55.1_Linux-64bit.deb && \
    dpkg -i trivy_0.55.1_Linux-64bit.deb && \
    rm trivy_0.55.1_Linux-64bit.deb

# Ensure Trivy DB update
RUN trivy image --download-db-only

# Create necessary directories
RUN mkdir -p /usr/src/app /mnt/output/deb_packages /mnt/output/sbom_results /mnt/output/trivy_results /mnt/output/logs

# Set up a virtual environment
RUN python3 -m venv /usr/src/app/venv

# Copy requirements.txt and install Python dependencies
COPY requirements.txt /usr/src/app/
RUN /usr/src/app/venv/bin/pip install -r /usr/src/app/requirements.txt

# Copy Python script and necessary files
COPY main.py packages.txt repos.txt /usr/src/app/

# Set working directory
WORKDIR /usr/src/app

# Ensure the script is executable
RUN chmod +x main.py

# Activate the virtual environment and run the Python script
CMD ["/usr/src/app/venv/bin/python", "main.py"]
