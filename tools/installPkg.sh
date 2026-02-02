#!/bin/bash

set -e

echo "Checking pysigma installation..."
if ! pip3 show pysigma > /dev/null 2>&1; then
    echo "pysigma not found. Installing..."
    pip3 install pysigma
else
    echo "pysigma already installed."
fi

echo "Checking pysigma_backend_fortisiem installation..."
if ! pip3 show pysigma-backend-fortisiem > /dev/null 2>&1; then
    echo "pysigma_backend_fortisiem not found. Installing..."

    # Clone repo if not already present
    if [ ! -d "pySigma-backend-fortisiem" ]; then
        echo "Cloning pySigma-backend-fortisiem repository..."
        git clone https://github.com/FortiSIEM/pySigma-backend-fortisiem.git
    else
        echo "Repository already exists."
    fi

    cd pySigma-backend-fortisiem

    echo "Building package..."
    python3 -m pip install --upgrade build
    python3 -m build

    echo "Installing wheel..."
    pip3 install dist/pysigma_backend_fortisiem-*.whl

    cd ..
else
    echo "pysigma_backend_fortisiem already installed."
fi

SCRIPT_PATH="$(realpath "$0")"
SCRIPT_DIR="$(dirname "$SCRIPT_PATH")"

echo "Script path: $SCRIPT_PATH"
echo "Script directory: $SCRIPT_DIR"

echo "Done."
