# Hysakrypt2

Super-simple (probably not very secure) file encryption utility. Useful if you need to encrypt a whole drive of files.

### Usage

##### Build

```
dotnet publish -c Release -o out
```

##### Encrypt

```
dotnet Hysakrypt2.dll encrypt [-f <file> OR -d <directory>] [-p <password>]
```

##### Decrypt

```
dotnet Hysakrypt2.dll decrypt [-f <file> OR -d <directory>] [-p <password>]
```

### Notes

- This is Hysakrypt2 as the original Hysakrypt was lost to the ether.
- Need to allow password input rather than command line.
- Hysakrypt2 can only decrypt files it encrypted.
- I'm not certain this is safe for prod/commercial use - *use at your own risk*
