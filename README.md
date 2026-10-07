# Sitio seguro

Un sitio para crear una cuenta e iniciar sesión con correo, contraseña y un código de tu app autenticadora.

## Instalar y abrir en Windows

Necesitas Python y Git instalados. Abre PowerShell y ejecuta:

```powershell
git clone https://github.com/Lexioor/ids-login-web.git
cd ids-login-web
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

Abre **http://localhost:8000** en tu navegador. Mantén PowerShell abierto; para detener el sitio, presiona **Ctrl+C**.

Para volver a abrirlo, entra en la carpeta del proyecto y ejecuta:

```powershell
.\.venv\Scripts\python.exe app.py
```

## Crear una cuenta

1. Pulsa **Regístrate**.
2. Escribe tu correo y una contraseña de entre 8 y 128 caracteres. Repite la contraseña.
3. Abre Google Authenticator, Microsoft Authenticator o Aegis y escanea el QR. También puedes usar la clave manual.
4. Introduce el código de 6 dígitos de la app para terminar el registro.

Necesitas conexión a Internet para validar el dominio del correo. No compartas el QR ni la clave de tu autenticador.

## Iniciar y cerrar sesión

Escribe tu correo y contraseña, pulsa **Continuar** e introduce el código actual de tu autenticador. Si acabas de usar un código, espera a que cambie. Si no funciona, comprueba que la hora de tu teléfono esté sincronizada.

Para salir, pulsa **Cerrar sesión** en el panel.

Hecho por Lex Cristofer Martinez Camarena.
