#!/bin/bash

echo "Select: 1) 10VM 2) 20VM 3) 30VM"
read -p "Choice: " choice

case $choice in
	1) ansible-playbook deploy.yaml -e "@10vm.yaml" ;;
	2) ansible-playbook deploy.yaml -e "@20vm.yaml" ;;
	3) ansible-playbook deploy.yaml -e "@30vm.yaml" ;;
	*) echo "Invalid option"; exit 1 ;;
esac
