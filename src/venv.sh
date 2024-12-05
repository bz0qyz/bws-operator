#!/usr/bin/env bash

if [[ ! -d .venv ]] || [[ -e ./venv/bin/activate ]]; then
    echo "Setting up python virtual environment"
    python3.12 -m venv .venv   
fi

echo "Activating virtual environment"
source .venv/bin/activate
echo "Installing modules"
pip3 --require-virtualenv install --upgrade -r ../requirements.txt

