#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Update package list and install prerequisites
sudo apt update
sudo apt install -y autoconf automake libtool git

# Create a directory for the libraries
mkdir -p ~/erasure_coding_libs
cd ~/erasure_coding_libs

# Clone, build, and install GF-Complete
if [ ! -d "gf-complete" ]; then
  git clone https://github.com/ceph/gf-complete.git
  cd gf-complete
  ./autogen.sh
  ./configure
  make
  sudo make install
  cd ..
else
  echo "GF-Complete already cloned. Skipping..."
fi

# Clone, build, and install Jerasure
if [ ! -d "Jerasure" ]; then
  git clone https://github.com/tsuraan/Jerasure.git
  cd Jerasure
  autoreconf --force --install
  ./configure
  make
  sudo make install
  cd ..
else
  echo "Jerasure already cloned. Skipping..."
fi

# Update the shared library cache
sudo ldconfig

echo "Installation of GF-Complete and Jerasure completed successfully."