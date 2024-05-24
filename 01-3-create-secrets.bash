#!/bin/bash

if [[ ${KUBECONFIG} == "" ]]
then
    echo "Please export KUBECONFIG env variable before running script!!!"
    exit 1
else
    echo "Current value of KUBECONFIG --> [${KUBECONFIG}]"
fi

SRC_FILE=.env
DST_FILE=/tmp/initial-secrets.yaml
SECRET=initial-secret
TMP_FILE=/tmp/${SECRET}.tmp

cat <<END > "${TMP_FILE}"
apiVersion: v1
kind: Secret
metadata:
  name: ${SECRET}
type: Opaque
data:
END

cat ${SRC_FILE} | while read line
do
  regex="^(.+?)=(.+)$"
  if [[ $line =~ $regex ]]; then

    KEY=$(echo -e "$line" | perl -0777 -ne 'print $1 if /^(.+?)=(.+)$/')
    VALUE=$(echo -e "$line" | perl -0777 -ne 'print $2 if /^(.+?)=(.+)$/')

    echo "  ${KEY}: $(echo -n "${VALUE}" | base64 -w0)" >> ${TMP_FILE}
  fi
done

BASIC_AUTH_FILE=/tmp/generic-basic-auth.txt
./99-utils/initial-basic-auth.sh ../secrets/generic-basic-auth.env ${BASIC_AUTH_FILE}
echo "  GENERIC_BASIC_AUTHEN: $(cat "${BASIC_AUTH_FILE}" | base64 -w0)" >> ${TMP_FILE}

GCP_SA=../secrets/rtarf.json
echo "  GCP_SA: $(cat "${GCP_SA}" | base64 -w0)" >> ${TMP_FILE}

cp ${TMP_FILE} ${DST_FILE}

kubectl apply -f ${DST_FILE}

#### Export ENV variables ###
export $(xargs <.env)

#### Github Authen ###
kubectl apply -f - <<END
apiVersion: v1
kind: Secret
metadata:
  name: github-auth-secret
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: repository
type: Opaque    
stringData:
  url: https://github.com/rtaf-soc/rtarf-rke2-labs-addons.git
  username: dummy-gh
  password: ${GH_TOKEN}
  type: git
END

### MinIO Secrets ###
kubectl apply -f - <<END
apiVersion: v1
kind: Secret
metadata:
  name: minio-ads-secret-env
type: Opaque
stringData:
  config.env: |-
    export MINIO_ROOT_USER=${MINIO_ACCESS_KEY}
    export MINIO_ROOT_PASSWORD=${MINIO_SECRET_KEY}
END

kubectl apply -f - <<END
apiVersion: v1
kind: Secret
metadata:
  name: minio-ads-user
type: Opaque
data:
  CONSOLE_ACCESS_KEY: $(echo -n "${CONSOLE_ACCESS_KEY}" | base64)
  CONSOLE_SECRET_KEY: $(echo -n "${CONSOLE_SECRET_KEY}" | base64)
END
