# Make sure installer_stub.sh is executable
chmod +x installer_stub.sh

# Create self-extracting setup.sh
{
  cat installer_stub.sh
  tar -czf - -C payload . | base64 -w 0
  echo
} > setup.sh

# Make setup.sh executable
chmod +x setup.sh