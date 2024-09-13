ARG UBUNTU_VERSION=24.04
FROM ubuntu:${UBUNTU_VERSION}

ENV DEBIAN_FRONTEND=noninteractive

# Install necessary dependencies
RUN apt-get update && \
    apt-get install --no-install-recommends -y python3-full python3-pip python3-venv apt-rdepends sudo curl clamav && \
    apt-get clean && \
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh

# Run freshclam to update ClamAV virus database
RUN freshclam

# Set correct permissions for the app and output directories
RUN mkdir -p /usr/src/app && chmod -R 777 /usr/src/app && mkdir -p /mnt/output && chmod -R 777 /mnt/output

# Set up the working directory
WORKDIR /usr/src/app

# Copy the current directory contents into the container
COPY . .

# Create a virtual environment and install dependencies
RUN python3 -m venv /usr/src/app/venv
RUN /usr/src/app/venv/bin/pip install --no-cache-dir -r requirements.txt

# Set environment variables for output directories
ENV PATH="/usr/src/app/venv/bin:$PATH"
ENV DEB_OUTPUT_DIR=/mnt/output/deb_packages
ENV LOG_OUTPUT_DIR=/mnt/output/logs

# Define the volume mount for output directories
VOLUME ["/mnt/output"]

# Set the default command to run the script
CMD ["python3", "main.py"]
