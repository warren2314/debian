#!/bin/bash

# Function to select Ubuntu version
select_ubuntu_version() {
    echo "Please select the Ubuntu version:"
    echo "1) Ubuntu 22.04"
    echo "2) Ubuntu 24.04"
    echo "3) Ubuntu 24.10"
    read -p "Select [1-3]: " version_choice
    version_choice=${version_choice:-1}  # Default to 1 if no input

    case "$version_choice" in
        1)
            UBUNTU_VERSION="22.04"
            ;;
        2)
            UBUNTU_VERSION="24.04"
            ;;
        3)
            UBUNTU_VERSION="24.10"
            ;;
        *)
            echo "Invalid selection. Defaulting to Ubuntu 22.04."
            UBUNTU_VERSION="22.04"
            ;;
    esac

    echo "Selected Ubuntu version: $UBUNTU_VERSION"
}

# Function to display the main menu
main_menu() {
    echo "Select the download method:"
    echo "1) Download packages via apt-get from repositories"
    echo "2) Direct download from full URLs"
    echo "3) Direct download using filenames with a base URL"
    read -p "Select [1-3]: " download_choice
}

# Function to set up the output directory
setup_output_directory() {
    OUTPUT_DIR="./output"
    mkdir -p "$OUTPUT_DIR/logs" "$OUTPUT_DIR/deb_packages" "$OUTPUT_DIR/sbom_results" "$OUTPUT_DIR/trivy_results"
}

# Main script execution
select_ubuntu_version
main_menu

case "$download_choice" in
    1)
        # Download via apt-get from repositories
        setup_output_directory
        rm -f urls.txt filenames.txt  # Ensure these are not used
        export DOWNLOAD_MODE="REPO"

        # Create empty filenames.txt and urls.txt to satisfy Dockerfile COPY
        touch filenames.txt
        touch urls.txt
        ;;
    2)
        # Direct download from full URLs
        read -p "Enter the filename containing the list of URLs (default: urls.txt): " urls_file
        urls_file=${urls_file:-urls.txt}
        if [ ! -f "$urls_file" ]; then
            echo "URLs file '$urls_file' does not exist."
            exit 1
        fi
        cp "$urls_file" urls.txt
        setup_output_directory
        export DOWNLOAD_MODE="URL"
        export DOWNLOAD_FILE="urls.txt"
        ;;
    3)
        # Direct download using filenames with a base URL
        read -p "Enter the filename containing the list of package filenames (default: filenames.txt): " filenames_file
        filenames_file=${filenames_file:-filenames.txt}
        if [ ! -f "$filenames_file" ]; then
            echo "Filenames file '$filenames_file' does not exist."
            exit 1
        fi
        read -p "Enter the base URL for downloading packages: " BASE_URL
        if [ -z "$BASE_URL" ]; then
            echo "Base URL cannot be empty."
            exit 1
        fi
        export BASE_URL="$BASE_URL"
        # No need to copy filenames.txt to itself
        setup_output_directory
        export DOWNLOAD_MODE="FILENAME"
        export DOWNLOAD_FILE="filenames.txt"
        ;;
    *)
        echo "Invalid selection."
        exit 1
        ;;
esac

# Build the Docker image, passing the Ubuntu version
echo "Building Docker image with Ubuntu version $UBUNTU_VERSION..."
docker build --build-arg UBUNTU_VERSION="$UBUNTU_VERSION" -t download-script .

# Run the Docker container with mounted output directory
docker run -it --rm -v "$(pwd)/output":/mnt/output \
    -e UBUNTU_VERSION="$UBUNTU_VERSION" \
    -e DOWNLOAD_MODE="$DOWNLOAD_MODE" \
    -e DOWNLOAD_FILE="$DOWNLOAD_FILE" \
    -e BASE_URL="$BASE_URL" \
    download-script