# 🚀 gabogalro/auth-middleware

- Middleware de autenticación para APIs en PHP, pensado para integrarse con el gabogalro/router.
- Permite proteger rutas mediante tokens de acceso **Bearer token** generados por la librería Token, evitando el acceso no autorizado.

## Instalación

```bash
composer require gabogalro/auth-middleware
```

## Guia de uso

- Tu token se envía en el header HTTP Authorization en el formato:
- Authorization: Bearer {token_id}|{token_plano}

### El middleware valida:

- Que exista el header Authorization.

- Que el token tenga formato válido (token_id|token_plano).

- Que el token exista en la base de datos, esté activo y no haya expirado.

#### Ejemplo de rutas protegidas

```php
use gabogalro\Router\Router;
use app\Controllers\UserController;
use gabogalro\AuthMiddleware\AuthMiddleware;

$router = new Router();

$router->group('/api', function ($router) {
    $router->group('/users', function ($router) {
        // Ruta pública
        $router->post('/register', [UserController::class, 'UsersMember']);

        // Ruta protegida por token
        $router->get('/get', [UserController::class, 'GetUserById'])
               ->withMiddleware('AuthMiddleware');
    });
});

// Dispatcher principal
$router->dispatch($_SERVER['REQUEST_METHOD'], $_SERVER['REQUEST_URI']);


```

## Respuestas del middleware

| Código HTTP | Condición                 | Respuesta JSON                                               |
| ----------- | ------------------------- | ------------------------------------------------------------ |
| 400         | Header malformado         | `{ "error": "Bad Request: Malformed Authorization header" }` |
| 401         | Header ausente            | `{ "error": "Unauthorized: Token missing" }`                 |
| 403         | Token inválido o expirado | `{ "error": "Forbidden: Invalid or expired token" }`         |
| 200         | Token válido              | Continúa al siguiente middleware o controlador               |

### Generación y validación de tokens

- Cada token generado sigue el formato:

```markdown
{token_id}|{token_plano}
```

### Ejemplo de generación de token

```php
use gabogalro\Token\Token;

$token = Token::generate_token($user_id);
// Devuelve algo como: 12|f4b1e7c3a4d2...

```

### Validación automática en rutas protegidas mediante AuthMiddleware.

### Ejemplo de logout

```php
use gabogalro\Auth\Auth;

Auth::logout($token);

```

### Flujo recomendado

- Register → Crear usuario.

- Login → Generar token token_id|token_plano.

- Ruta protegida → Enviar token en header Authorization.

- Logout → Invalidar token cuando el usuario cierra sesión.

## Requisitos previos

- PHP 7.4 o superior
- Composer
- [php-api-router](https://github.com/EduardoGalindo25/php-api-router)

## License

MIT © gabogalro. See [LICENSE](LICENSE) for details.
