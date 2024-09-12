### Decrypting VNC password

```
echo -n 48F6A97D99A334976B | xxd -r -p | openssl enc -des-cbc --nopad --nosalt -K e84ad660c4721ae0 -iv 0000000000000000 -d | hexdump -Cv
```
