#This script is used to upgrade pySigma-backend-fortisiem to support new version of pysigma
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <pysigma_desired_version> <fortisiem_backend_version>"
    echo "Example: $0 0.11.5 0.2.0"
    exit 1
fi

pysigma_desired_version="$1"
fortisiem_backend_version="$2"

### install pySigma ###
if pip3.9 list | grep "pySigma "; then
    installed_version=$(pip3.9 show pySigma | grep Version | cut -d " " -f 2)
    echo "Installed version of pySigma: $installed_version"

    # Compare installed version with desired version
    if [ "$installed_version" = "$pysigma_desired_version" ]; then
        echo "pySigma is already installed and matches the desired version ($pysigma_desired_version)."
    else
        # Remove the old version of pySigma
        echo "Removing the old version of pySigma..."
        pip3.9 uninstall -y pySigma
        echo "Old version of pySigma removed."

        echo "Installing pySigma version $pysigma_desired_version..."
        # Install the new version of pySigma
        pip3.9 install --user --upgrade pySigma==$pysigma_desired_version
        echo "pySigma version $pysigma_desired_version installed."

    fi
else
    echo "pySigma is not installed. Installing pySigma version $pysigma_desired_version..."
    # Install pySigma if it's not installed
    pip3.9 install --user pySigma==$pysigma_desired_version
    echo "pySigma version $pysigma_desired_version installed."
fi


### Install cookiecutter ###
#https://github.com/SigmaHQ/cookiecutter-pySigma-backend
if pip3.9 list | grep "cookiecutter "; then
    echo "cookiecutter is already installed."
else
    echo "cookiecutter is not installed. Installing..."
    python3.9 -m pip install --user cookiecutter
fi

### Generate new projects
redownloadedcookiecutters=y
target_name="FortiSIEM"
backend_package_name=""
backend_name=""
backend_class_name=""
package_type=""
package_name=""
package_description=""
author="Mei Liu"
email="meiliu@fortinet.com"
license=""
github_account="FortiSIEM"
test_badge=""
coverage_badge=""
coverage_gist=""
status_badge=""
selectstatus=""
additional_output_formats=n
output_formats=""


# Run Cookiecutter with input redirection
cookiecutter https://github.com/SigmaHQ/cookiecutter-pySigma-backend.git <<EOF
$redownloadedcookiecutters
$target_name
$backend_package_name
$backend_name
$backend_class_name
$package_type
$package_name
$package_description
$author
$email
$license
$github_account
$test_badge
$coverage_badge
$coverage_gist
$status_badge
$selectstatus
$additional_output_formats
$output_formats
EOF


cp -rf pySigma-backend-fortisiem/LICENSE .
cp -rf pySigma-backend-fortisiem/poetry.lock .
cp -rf pySigma-backend-fortisiem/pyproject.toml .
cp -rf pySigma-backend-fortisiem/README.md .

sed -i "s/version.*/version = \"$fortisiem_backend_version\"/" pyproject.toml
