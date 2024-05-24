#!/bin/bash

if [[ ${KUBECONFIG} == "" ]]
then
    echo "Please export KUBECONFIG env variable before running script!!!"
    exit 1
else
    echo "Current value of KUBECONFIG --> [${KUBECONFIG}]"
fi

export $(xargs <.env)

cd "01-4-openebs"
helm dependency update
helm upgrade -i init-openebs . -f values-${ENV}.yaml -n openebs --create-namespace
cd ..
