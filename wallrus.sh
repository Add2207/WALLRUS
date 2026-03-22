#!/bin/bash
cd ~/wallrus
source venv/bin/activate
PYTHONPATH=src python -m wallrus.cli.main "$@"
echo 'alias wallrus="~/wallrus/wallrus.sh"' >> ~/.bashrc
