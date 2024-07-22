# Test Data for Sudo Secure Id Verification

## Folder Structure

The folder structure for the test images are organized by identity verification service provider and capability.

| Folder              | Contents |
| ------------------- | -------- |
|    IDology-sandbox-V2/ScanOnboard/     | IDology's ScanOnboard capability - multiple use cases and image formats |
|    IDology-sandbox-V2/ScanVerify/      | IDology's ScanVerify capability - multiple use cases and image formats |
| Simulator/          | Sudo Platform internal simulator |


## Other Notes

1. For verification using passport, use the same passport image for front and back fields.

2. The text files (with `.txt` extension) contains the Base 64 encoded data of the image file with the corresponding name.

3. For the Sudo Platform internal simulator, the same image files can be used for document verification and onboarding with identity document use cases.
