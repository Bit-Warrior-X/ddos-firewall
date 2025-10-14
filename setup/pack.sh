# Make sure installer_stub.sh is executable
chmod +x installer_stub.sh

rm -rf /usr/local/openresty/nginx/logs/*
rm -rf /usr/local/openresty/nginx/sbin/nginx.old
rm -rf payload/l7/openresty.tar.gz

tar -zcf payload/l7/openresty.tar.gz -C /usr/local openresty
# Create self-extracting setup.sh
{
  cat installer_stub.sh
  tar -czf - -C payload . | base64 -w 0
  echo
} > setup.sh

# Make setup.sh executable
chmod +x setup.sh
