
# One-Time Password Generator

Este programa es una aplicación de escritorio desarrollada en Python utilizando la biblioteca tkinter. Genera contraseñas de un solo uso (OTP) utilizando una clave maestra que es encriptada y almacenada en un archivo. Adicionalmente, el programa permite generar códigos QR con la OTP generada para facilitar su uso.

## Requisitos

Antes de ejecutar el programa, asegúrese de tener instaladas las siguientes bibliotecas de Python:

-   hashlib
-   hmac
-   math
-   time
-   struct
-   pyotp
-   qrcode
-   cryptography
-   os
-   base64
-   tkinter
-   PIL (Pillow)

Puede instalar las bibliotecas requeridas utilizando el siguiente comando:


```
pip install pyotp qrcode cryptography pillow

```

## Uso

1.  Ejecute el programa en Python:  `python ft_otp.py`
2.  Haga clic en "Generate Key File" para crear la clave maestra en un archivo llamado  `key.hex`.
3.  Ingrese una contraseña de encriptación en el campo "Encryption Password".
4.  Haga clic en "Encrypt Key File" para encriptar la clave maestra y guardarla en un archivo llamado  `ft_otp.key`.
5.  Cargue el archivo de clave maestra encriptado haciendo clic en "Load Master Key" y seleccionando el archivo  `ft_otp.key`.
6.  El programa generará una OTP y la mostrará en el campo "OTP".
7.  Haga clic  en "Generate QR Code" para generar un código QR con la OTP. El código QR se mostrará en la ventana de la aplicación.

## Nota

Este programa se proporciona con fines educativos y de demostración. No se recomienda su uso en entornos de producción sin una revisión y actualización adecuadas de la seguridad y el cifrado.
