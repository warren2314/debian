#!/bin/bash

# Ensure the directory for PostgreSQL GPG keys exists
mkdir -p /usr/share/postgresql-common/pgdg

# Download the PostgreSQL GPG key
curl -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc --fail https://www.postgresql.org/media/keys/ACCC4CF8.asc

# Add the PostgreSQL repository to the sources list
sh -c 'echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list'

# Update package lists
apt-get update

