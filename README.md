# SecurePass Manager 🔒

Un gestor de contraseñas seguro y local, desarrollado en Python con cifrado AES-256. Diseñado para proteger tus credenciales con tecnología robusta y una interfaz intuitiva.

![Captura de pantalla](https://via.placeholder.com/800x500.png?text=Interfaz+SecurePass+Manager) *(Reemplazar con captura real)*

## Características Clave 🚀
- **🔐 Cifrado Fuerte**: AES-256 con derivación PBKDF2-HMAC
- **🛡️ Autenticación Maestra**: Acceso seguro con contraseña principal
- **📋 Gestión Completa**:
  - Añadir nuevas entradas
  - Editar/eliminar registros
  - Generador de contraseñas seguras
  - Copiado al portapapeles
- **💾 Almacenamiento Local**: Base de datos SQLite encriptada
- **🎨 Interfaz Moderna**: Tema oscuro y diseño intuitivo

## Tecnologías Utilizadas 💻
- **Lenguaje**: Python 3.10+
- **Cifrado**: Biblioteca `cryptography`
- **Base de Datos**: SQLite
- **Interfaz**: Tkinter
- **Gestión de Contraseñas**: Módulo `secrets`

## Instalación ⚙️
1. Clona el repositorio:
```bash
git clone https://github.com/tuusuario/securepass-manager.git
cd securepass-manager
