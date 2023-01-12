echo Creating keys and certificates
keytool -genkeypair -keyalg RSA -keysize 2048 -alias senderkey -keystore senderkeystore.jks -storepass senderpassword -keypass senderpassword -storetype JKS -dname "CN=Sender, OU=My Org, O=My Org, L=My City, S=My State, C=US"
keytool -genkeypair -keyalg RSA -keysize 2048 -alias receiverkey -keystore receiverkeystore.jks -storepass receiverpassword -keypass receiverpassword  -storetype JKS -dname "CN=Receiver, OU=My Org, O=My Org, L=My City, S=My State, C=US"
echo Exporting certificates
keytool -exportcert -alias senderkey -keystore senderkeystore.jks -file sendercertificate.crt -storepass senderpassword
keytool -exportcert -alias receiverkey -keystore receiverkeystore.jks -file receivercertificate.crt -storepass receiverpassword
echo Importing certificates
keytool -importcert -noprompt -alias receivercert -file receivercertificate.crt -keystore senderkeystore.jks -storepass senderpassword
keytool -importcert -noprompt -alias sendercert -file sendercertificate.crt -keystore receiverkeystore.jks -storepass receiverpassword
