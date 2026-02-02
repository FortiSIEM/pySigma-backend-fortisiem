if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <clone_url> <sigma_commit_id_1>" 
    exit 1
fi
clone_url=$1

if [ "$#" -gt 1 ]; then
    commit1=$2
fi

sigma_repo_dir="sigma"
echo "Get SigmaHQ/sigma"
if [ -d "$sigma_repo_dir" ]; then
    echo "Pulling latest changes..."
    echo "Goto $sigma_repo_dir"
    echo ""
    cd $sigma_repo_dir
    git pull
else
    echo "Cloning the repository..."
    #git clone git@github.com:SigmaHQ/sigma.git $sigma_repo_dir
    git clone $clone_url $sigma_repo_dir
    echo "Goto $sigma_repo_dir"
    echo ""
    cd $sigma_repo_dir
fi

if [ -n "$commit1" ]; then
    git reset --hard $commit1
fi

cd ../
if [ ! -e "./rules" ]; then
    ln -s $sigma_repo_dir/rules ./rules
else
    echo "rules already exists"
fi
exit 0
