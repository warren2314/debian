#!/bin/bash

echo "Please select the Ubuntu version (default is 22.04):"
echo "1) Ubuntu 22.04"
echo "2) Ubuntu 24.04"
read -p "Select [1-2]: " version_choice

# Set the correct Ubuntu version based on user input or default
if [ "$version_choice" == "2" ]; then
    UBUNTU_VERSION="24.04"
else
    UBUNTU_VERSION="22.04"
fi

# Prompt user for the output directory
read -p "Enter the directory to store logs and deb files (default: ./output): " output_dir

# Use the default value if the user leaves it blank
output_dir=${output_dir:-./output}

# Create necessary directories on the host
mkdir -p "$output_dir/logs" "$output_dir/deb_packages"

# Build the Docker image
docker build --build-arg UBUNTU_VERSION=$UBUNTU_VERSION -t download-script .

# Run the Docker container, ensuring the full output directory is mounted
docker run -it --rm -v $(realpath "$output_dir"):/mnt/output download-script