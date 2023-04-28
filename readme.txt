# README

## Project Workflow

This project consists of two main modules, which are designed to generate encryption keys, encrypt plaintext, and perform cryptanalysis on the ciphertext. Here is the step-by-step workflow of the project:

1. Run `keyGenUI.py` to open the Key Generator UI window.
2. Run `CipherGenerationUI.py` to open the Encryption Tool UI window.
3. In the Key Generator window, choose the encryption algorithm (DES, RSA, or Vigenere) from the drop-down menu.
4. Click on the "Generate Key" button to create the encryption key for the selected algorithm.
5. Use the "Copy Key" button to copy the generated key to the clipboard, or click on "Save Key to the File" to save the key in a text file.
6. In the Encryption Tool window, input the plaintext you want to encrypt.
7. Select the same encryption algorithm from the drop-down menu as chosen in the Key Generator window.
8. Paste the copied key into the "Secret Key" text box.
9. Click on the "Encrypt and Save" button to encrypt the plaintext and save the ciphertext. The plaintext, keys, and ciphertexts are saved in separate text files and displayed in the result box within the window.

This completes the first module of the project.

10. Run the `SecondModule.py` to open the Cryptanalysis UI window.
11. Click on the "Open Cipher Texts and Plain Texts from Files" button to load the ciphertexts and plaintexts from their respective text files.
12. Choose the encryption algorithm from the drop-down menu, the same one used in the first module.
13. Click on the "Decrypt and Show" button to perform cryptanalysis on the loaded ciphertexts. The decrypted plaintext will be displayed in the result box.
14. The frequency analysis graphs for the plaintext and ciphertext are also generated and displayed in the Cryptanalysis UI window.

This concludes the second module of the project, showcasing the complete workflow of the encryption and cryptanalysis processes.