#!/bin/bash

path="./libs/zbor"

echo "Checking if '$path' does already exist"

if [[ -d $path ]]; then
    echo -e "\x1b[32mfound\x1b[0m"
    cd $path
    git pull origin master
    cd ../..
else
    echo "Trying to connect to github.com via ssh to clone zbor..."
    response=$(ssh -T git@github.com 2>&1)
    if [[ $response == *"successfully authenticated"* ]]; then
        echo -e "\x1b[32msuccess:\x1b[0m cloning zbor via ssh"
        git clone git@github.com:r4gus/zbor.git $path
    else
        echo -e "\x1b[33mfailure:\x1b[0m cloning zbor via https"
        git clone https://github.com/r4gus/zbor.git $path
    fi
fi
