#!/usr/bin/env bash
# Generación Automática de Claves de Firma Segura (Offline/Vaulted)
set -eo pipefail

echo "[+] HispaShield Mobile - Key Generation Script"
echo "[!] ESTE SCRIPT DEBE GENERARSE EN UN ENTORNO AISLADO (COLD STORAGE/AIR GAPPED)"

KEYS_DIR="../security/release_keys"
mkdir -p "$KEYS_DIR"

if [ -f "$KEYS_DIR/releasekey.pk8" ]; then
    echo "[-] Las claves maestras ya existen. Abortando para evitar sobrescritura y pérdida de la cadena AVB."
    exit 1
fi

SUBJECT="/C=ES/ST=Madrid/L=Madrid/O=HispaShield/OU=MobileOS/CN=HispaShield Release Key"

echo "[+] Generando claves RSA 4096 / SHA-256 para Android Verified Boot y Sistema..."
for keyname in releasekey platform shared media networkstack sdk_sandbox bluetooth; do
    echo "  -> Generando $keyname"
    openssl req -new -x509 -sha256 -days 10000 -nodes \
        -newkey rsa:4096 \
        -out "$KEYS_DIR/$keyname.x509.pem" \
        -keyout "$KEYS_DIR/$keyname.pem" \
        -subj "$SUBJECT" > /dev/null 2>&1

    # Convertir formato private key a pk8 nativo de AOSP
    openssl pkcs8 -in "$KEYS_DIR/$keyname.pem" -topk8 -outform DER -out "$KEYS_DIR/$keyname.pk8" -nocrypt
    
    # Secure purge of the intermediate pem 
    rm "$KEYS_DIR/$keyname.pem"
done

echo "[+] Claves generadas exitosamente de forma offline en $KEYS_DIR."
echo "    -> Almacena este directorio en un HSM YubiKey o módulo PGP antes del despliegue OTA."
