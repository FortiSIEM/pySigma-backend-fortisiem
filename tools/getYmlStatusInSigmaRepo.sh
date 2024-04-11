#!/bin/bash
#
# This script is to get the yml file status in sigma repo

#Example: 
# 1. to get the changes of yml files under sigma
#      getYmlStatusInSigmaRepo.sh sigma "7f3eff58e17c1edec877cf45972726588d009940" "9078b857a186f19cd9b1c7f939df989b0bb5ca4b" changes.csv 
# 2. to get the changes of yml files under sigma/rules
#      getYmlStatusInSigmaRepo.sh sigma "7f3eff58e17c1edec877cf45972726588d009940" "9078b857a186f19cd9b1c7f939df989b0bb5ca4b" changes.csv rules 

if [ "$#" -lt 4 ]; then
    echo "Usage: $0 <repo_dir> <commit_id_1> <commit_id_2> <output_csv> <diff_path>"
    exit 1
fi
# Define the repository directory
repo_dir=$1
commit1=$2
commit2=$3
output_csv=$4
diff_path=""
diff_path=""
if [ "$#" == 5 ]; then
   diff_path="$5"
fi

# Check if the repository directory exists
if [ -d "$repo_dir" ]; then
    echo "Repository directory exists. Pulling latest changes..."
    cd $repo_dir
    git pull
else
    echo "Repository directory does not exist. Cloning the repository..."
    git clone git@github.com:SigmaHQ/sigma.git $repo_dir
    cd $repo_dir
fi


echo "git diff in $repo_dir/$diff_path"
# Define the two commit IDs from the script arguments
# Output the CSV header
echo "status,oldfilename,newfilename" > $output_csv

# Compare the two commits and filter for .yml files
# Then format the output into the desired CSV format
git diff --name-status $commit1 $commit2 $diff_path | grep '\.yml$' |grep -v '.github/' | awk '{print $1","$2","$3}' >> $output_csv

# Move the CSV file to the parent directory
if [[ $diff_path != *'/'* ]]; then
    mv $output_csv ..
fi

# Navigate back to the parent directory
cd ..

echo "CSV file with changes has been created as $output_csv"

