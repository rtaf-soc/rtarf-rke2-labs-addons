#!/bin/bash

KIBANA_URL=https://es-ads-kb-http:5601/api/saved_objects/_export
FNAME=$(date +%Y%m%d_%H%M%S).ndjson
EXPORTED_FILE=/tmp/${FNAME}
GCS_PATH=gs://${BUCKET_NAME}/kibana-2-saved-objects/${FNAME}

gcloud auth activate-service-account --key-file=${GOOGLE_APPLICATION_CREDENTIALS}

curl -k -X POST "${KIBANA_URL}" -H 'kbn-xsrf: true' -H 'Content-Type: application/json' -u "${ES_USER}:${ES_PASSWORD}" -d '
{
  "type": ["dashboard", "visualization", "index-pattern"],
  "includeReferencesDeep": true
}' > ${EXPORTED_FILE}

gsutil cp ${EXPORTED_FILE} ${GCS_PATH}

### slack notify ###

FILE_SIZE=$(stat -c%s ${EXPORTED_FILE})
TMP_TEMPLATE=/tmp/${FNAME}-slack.json
# NOTE : SLACK_URI is injected via env variable
OBJECT_CNT=$(wc -l ${EXPORTED_FILE} | cut -d' ' -f1)

cat << EOF > ${TMP_TEMPLATE}
{
    "text": "Done uploading files [${EXPORTED_FILE}], file size=[${FILE_SIZE}], object count=[${OBJECT_CNT}]\n"
}
EOF
curl -X POST -H 'Content-type: application/json' --data "@${TMP_TEMPLATE}" ${SLACK_URI}
