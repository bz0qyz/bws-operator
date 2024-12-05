#!/usr/bin/env bash

py3=python3.12

${py3} -m pip install --upgrade -r requirements.txt \
&& ${py3} -m PyInstaller --clean -F -n bws-operator src/main.py