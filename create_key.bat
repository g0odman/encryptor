rem 
keytool -genkeypair -keyalg RSA -keysize 2048 -alias encryptionkey -keystore privatekeystore.jks -storepass storepassword -storetype JKS -dname "CN=My Name, OU=My Org, O=My Org, L=My City, S=My State, C=US"
keytool -genkeypair -keyalg RSA -keysize 2048 -alias encryptionkey -keystore publickeystore.jks -storepass storepassword -storetype JKS -dname "CN=My Name, OU=My Org, O=My Org, L=My City, S=My State, C=US"
keytool -certreq -alias encryptionkey -keystore mykeystore.jks -file mycert.csr
keytool -importcert -alias encryptionkey -file mycert.crt -keystore mykeystore.jks
