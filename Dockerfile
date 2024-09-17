ARG UBUNTU_VERSION=22.04
FROM ubuntu:${UBUNTU_VERSION}

# Install necessary tools
RUN apt-get update && apt-get install -y \
    apt-utils \
    apt-rdepends \
    curl \
    ca-certificates \
    wget \
    clamav \
    python3 \
    python3-pip \
    python3-venv \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

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

# Activate the virtual environment and install requests
RUN /usr/src/app/venv/bin/pip install requests

# Copy Python script
COPY main.py /usr/src/app/main.py

# Activate the virtual environment and run the Python script
WORKDIR /usr/src/app
CMD ["/usr/src/app/venv/bin/python", "main.py"]
