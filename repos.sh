#!/bin/bash

# ----------------------------------------
# PostgreSQL Installation
# ----------------------------------------

# Ensure the directory for PostgreSQL GPG keys exists
sudo mkdir -p /usr/share/postgresql-common/pgdg

# Download the PostgreSQL GPG key
sudo curl -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc --fail https://www.postgresql.org/media/keys/ACCC4CF8.asc

# Add the PostgreSQL repository to the sources list
sudo sh -c 'echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list'


# ----------------------------------------
# Erlang Installation
# ----------------------------------------

# Ensure the directory for Erlang GPG keys exists
sudo mkdir -p /usr/share/keyrings

# Download the Erlang GPG key
sudo curl -o /usr/share/keyrings/erlang_solutions.asc --fail https://packages.erlang-solutions.com/ubuntu/erlang_solutions.asc

# Add the Erlang repository to the sources list
sudo sh -c 'echo "deb [signed-by=/usr/share/keyrings/erlang_solutions.asc] https://packages.erlang-solutions.com/ubuntu $(lsb_release -cs) contrib" > /etc/apt/sources.list.d/erlang_solutions.list'


# ----------------------------------------
# Terraform Installation
# ----------------------------------------

# Download the HashiCorp GPG key for Terraform
sudo curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo tee /usr/share/keyrings/hashicorp-archive-keyring.gpg > /dev/null

# Add the HashiCorp repository to the sources list
sudo sh -c 'echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" > /etc/apt/sources.list.d/hashicorp.list'


# ----------------------------------------
# Puppet Installation
# ----------------------------------------

# Download the Puppet GPG key
sudo curl -o /usr/share/keyrings/puppet.asc --fail https://apt.puppet.com/DEB-GPG-KEY-puppet

# Add the Puppet repository to the sources list
sudo sh -c 'echo "deb [signed-by=/usr/share/keyrings/puppet.asc] http://apt.puppet.com $(lsb_release -cs) puppet6" > /etc/apt/sources.list.d/puppet.list'


# ----------------------------------------
# Update Package Lists
# ----------------------------------------

# Update the package lists after adding all repositories
sudo apt-get update

