#!/bin/env bash
# Assuming you just did: `vault server -dev`
export VAULT_ADDR='http://127.0.0.1:8200'
vault auth enable approle
echo 'path "secret/*" { capabilities = ["read"] }' | vault policy write get-da-secrets -
vault write auth/approle/role/get-da-secrets policies="get-da-secrets"
vault kv put secret/user user=apg password=hunter2

echo "Put this in your environment"

echo export VAULT_ADDR=${VAULT_ADDR}
echo export APPROLE_ROLE_ID="$(vault read -field=role_id auth/approle/role/get-da-secrets/role-id)"
echo export APPROLE_SECRET_ID="$(vault write -f -field=secret_id auth/approle/role/get-da-secrets/secret-id)"
echo export APPROLE_PATH="approle"
echo

cat <<EOF
And now you can run:

envbreach -e dotenv /bin/env
EOF
