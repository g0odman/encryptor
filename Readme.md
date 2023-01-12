# Hybrid Encryptor
`
## Encryption side
```ini
inputFile=input.txt
outputFile=output.txt
keyStoreFile=senderkeystore.jks
KeyStorePassword=senderpassword
AsymetricAlgorithm=RSA
SymetricAlgorithm=AES
KeyStoreType=JKS
keyAlias=senderkey
certificateAlias=receivercert
outConfigFile=decryption.properties
```

## Decryption side
The previous stage outputs the following
```ini
KeyStorePassword=storepassword
inputFile=output.txt
AsymetricAlgorithm=RSA
KeyStoreType=JKS
secretKey=[B@65e579dc
keyAlias=encryptionkey
digitalSignature=[B@52d455b8
keyStoreFile=mykeyStore.jks
SymetricAlgorithm=AES
```

We need to add an output file to this 