#!/bin/bash

IMG_URL=https://raw.githubusercontent.com/rtaf-soc/rtarf-public-artifacts/main/logocyberB.svg
IMAGE_DIR=/usr/share/grafana/public/img

wget -P ${IMAGE_DIR} ${IMG_URL}
cp ${IMAGE_DIR}/logocyberB.svg ${IMAGE_DIR}/grafana_icon.svg

sh /run.sh
