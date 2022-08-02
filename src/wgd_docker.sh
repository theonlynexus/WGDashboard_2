#!/bin/bash

# wgd.sh - Copyright(C) 2021 Donald Zou [https://github.com/donaldzou]
# Under Apache-2.0 License
app_name="dashboard.py"
app_official_name="WGDashboard"
PID_FILE=./gunicorn.pid
environment=$(if [[ $ENVIRONMENT ]]; then echo $ENVIRONMENT; else echo 'develop'; fi)
CONFIGURATION_PATH="/config"

if [[ $CONFIGURATION_PATH ]]; then
  cb_work_dir=$CONFIGURATION_PATH/letsencrypt/work-dir
  cb_config_dir=$CONFIGURATION_PATH/letsencrypt/config-dir
else
  cb_work_dir=/etc/letsencrypt
  cb_config_dir=/var/lib/letsencrypt
fi

certbot_create_ssl () {
  certbot certonly --config ./certbot.ini --email "$EMAIL" --work-dir $cb_work_dir --config-dir $cb_config_dir --domain "$SERVERURL"
}

certbot_renew_ssl () {
  certbot renew --work-dir $cb_work_dir --config-dir $cb_config_dir
}

gunicorn_start () {
  printf "%s\n" "$dashes"
  printf "| Starting WGDashboard with Gunicorn in the background.    |\n"
  d=$(date '+%Y%m%d%H%M%S')
  if [[ $USER == root ]]; then
    export PATH=$PATH:/usr/local/bin:$HOME/.local/bin
  fi
  gunicorn --access-logfile /log/access_"$d".log \
  --error-logfile /log/error_"$d".log 'dashboard:run_dashboard()'
  printf "| Log files is under log/                                  |\n"
  printf "%s\n" "$dashes"
}

gunicorn_stop () {
  kill $(cat ./gunicorn.pid)
}


generate_confs () {
  mkdir -p /config/server
  if [ ! -f /config/server/privatekey-server ]; then
    umask 077
    wg genkey | tee /config/server/privatekey-server | wg pubkey > /config/server/publickey-server
  fi
  eval "`printf %s`
  cat <<DUDE > /config/wg0.conf
`cat /config/templates/server.conf`

DUDE"
  for i in ${PEERS_ARRAY[@]}; do
    if [[ "${i}" =~ ^[0-9]+$ ]]; then
      PEER_ID="peer${i}"
    else
      PEER_ID="peer_${i//[^[:alnum:]_-]/}"
    fi
    mkdir -p /config/${PEER_ID}
    if [ ! -f "/config/${PEER_ID}/privatekey-${PEER_ID}" ]; then
      umask 077
      wg genkey | tee /config/${PEER_ID}/privatekey-${PEER_ID} | wg pubkey > /config/${PEER_ID}/publickey-${PEER_ID}
      wg genpsk > /config/${PEER_ID}/presharedkey-${PEER_ID}
    fi
    if [ -f "/config/${PEER_ID}/${PEER_ID}.conf" ]; then
      CLIENT_IP=$(cat /config/${PEER_ID}/${PEER_ID}.conf | grep "Address" | awk '{print $NF}')
      if [ -n "${ORIG_INTERFACE}" ] && [ "${INTERFACE}" != "${ORIG_INTERFACE}" ]; then
        CLIENT_IP=$(echo "${CLIENT_IP}" | sed "s|${ORIG_INTERFACE}|${INTERFACE}|")
      fi
    else
      for idx in {2..254}; do
        PROPOSED_IP="${INTERFACE}.${idx}"
        if ! grep -q -R "${PROPOSED_IP}" /config/peer*/*.conf && ([ -z "${ORIG_INTERFACE}" ] || ! grep -q -R "${ORIG_INTERFACE}.${idx}" /config/peer*/*.conf); then
          CLIENT_IP="${PROPOSED_IP}"
          break
        fi
      done
    fi
    if [ -f "/config/${PEER_ID}/presharedkey-${PEER_ID}" ]; then
      # create peer conf with presharedkey
      eval "`printf %s`
      cat <<DUDE > /config/${PEER_ID}/${PEER_ID}.conf
`cat /config/templates/peer.conf`
DUDE"
      # add peer info to server conf with presharedkey
      cat <<DUDE >> /config/wg0.conf
[Peer]
# ${PEER_ID}
PublicKey = $(cat /config/${PEER_ID}/publickey-${PEER_ID})
PresharedKey = $(cat /config/${PEER_ID}/presharedkey-${PEER_ID})
DUDE
    else
      echo "**** Existing keys with no preshared key found for ${PEER_ID}, creating confs without preshared key for backwards compatibility ****"
      # create peer conf without presharedkey
      eval "`printf %s`
      cat <<DUDE > /config/${PEER_ID}/${PEER_ID}.conf
`cat /config/templates/peer.conf | sed '/PresharedKey/d'`
DUDE"
      # add peer info to server conf without presharedkey
      cat <<DUDE >> /config/wg0.conf
[Peer]
# ${PEER_ID}
PublicKey = $(cat /config/${PEER_ID}/publickey-${PEER_ID})
DUDE
    fi
    SERVER_ALLOWEDIPS=SERVER_ALLOWEDIPS_PEER_${i}
    # add peer's allowedips to server conf
    if [ -n "${!SERVER_ALLOWEDIPS}" ]; then
      echo "Adding ${!SERVER_ALLOWEDIPS} to wg0.conf's AllowedIPs for peer ${i}"
      cat <<DUDE >> /config/wg0.conf
AllowedIPs = ${CLIENT_IP}/32,${!SERVER_ALLOWEDIPS}

DUDE
    else
      cat <<DUDE >> /config/wg0.conf
AllowedIPs = ${CLIENT_IP}/32

DUDE
    fi
    if [ -z "${LOG_CONFS}" ] || [ "${LOG_CONFS}" = "true" ]; then
      echo "PEER ${i} QR code:"
      qrencode -t ansiutf8 < /config/${PEER_ID}/${PEER_ID}.conf
    else
      echo "PEER ${i} conf and QR code png saved in /config/${PEER_ID}"
    fi
    qrencode -o /config/${PEER_ID}/${PEER_ID}.png < /config/${PEER_ID}/${PEER_ID}.conf
  done
}

[[ ! -f /config/templates/server.conf ]] && \
  cp /defaults/server.conf /config/templates/server.conf

[[ ! -f /config/templates/peer.conf ]] && \
  cp /defaults/peer.conf /config/templates/peer.conf

# add preshared key to user templates (backwards compatibility)
if ! grep -q 'PresharedKey' /config/templates/peer.conf; then
  sed -i 's|^Endpoint|PresharedKey = \$\(cat /config/\${PEER_ID}/presharedkey-\${PEER_ID}\)\nEndpoint|' /config/templates/peer.conf
fi

if [ ! -f /config/wg0.conf ]; then
    echo "**** No wg0.conf found (maybe an initial install), generating 1 server and ${PEERS} peer/client confs ****"
    generate_confs
fi

# gunicorn_start
flask run --host="0.0.0.0" --port="80"


