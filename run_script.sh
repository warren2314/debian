#!/bin/bash

echo "Please select the Ubuntu version (default is 22.04):"
echo "1) Ubuntu 22.04"
echo "2) Ubuntu 24.04"
read -p "Select [1-2]: " version_choice

if [ "$version_choice" == "2" ]; then
    UBUNTU_VERSION="24.04"
else
    UBUNTU_VERSION="22.04"
fi

read -p "Enter the directory to store logs and deb files (default: ./output): " output_dir
output_dir=${output_dir:-./output}

mkdir -p "$output_dir/logs" "$output_dir/deb_packages" "$output_dir/sbom_results" "$output_dir/trivy_results"

# Build the Docker image
docker build --build-arg UBUNTU_VERSION=$UBUNTU_VERSION -t download-script .

# Run the Docker container with mounted output directory
docker run -it --rm -v "$(pwd)/$output_dir":/mnt/output download-script
