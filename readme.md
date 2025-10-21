# 🚀 gabogalro/auth-library

- Libreria para generar tokens de autorización en headers que permite una protección de rutas adecuada.

## Instalación

```bash
composer require gabogalro/auth-library
```

## Guia de uso

- para que funcione correctamente esta libreria necesitas ejecutar los siguientes scripts

```sql
-- tabla de tokens para auth MySQL
create table tokens(
id_token int auto_increment primary key,
id_usuario int not null,
token varchar(255) not null unique,
fingerprint char(64) null,
created_at datetime,
expires_at datetime,
is_active bool
);

-- procedimiento almacenado necesario para el funcionamiento
CREATE PROCEDURE `sp_generate_token`(
in p_id_usuario int,
in p_token varchar(255),
in p_fingerprint char(64),
in p_expires_at datetime
)
begin
	declare p_id_token int;
	insert into tokens(id_usuario, token, fingerprint,created_at, expires_at, is_active)
	values(p_id_usuario, p_token, p_fingerprint ,now(), p_expires_at, 1);

	set p_id_token = LAST_INSERT_ID();
	select p_id_token as id_token;
END

-- procedimiento almacenado necesario para validar

CREATE PROCEDURE `sp_validate_token`(
in p_id_token int
)
begin

	select t.token, t.fingerprint
	from tokens t
	where t.id_token = p_id_token
	and t.is_active = 1
	and t.expires_at > now();
END
```

#### Ejemplo de generacion de token en un login

```php
use Exception;
use gabogalro\SQLHelpers\DB; // -> libreria para el uso de SQL
use gabogalro\Token\Token;

 public function login($request)
    {
        try {
            $user_data = [
                'email' => $request['email'],
                'password' => $request['password']
            ];
            if (empty($user_data['email']) || empty($user_data['password'])) {
                throw new Exception('Email y contraseña son obligatorios');
            }
            $result = DB::selectOne('call sp_login(?)', $user_data['email']); //-> parte de la libreria SQL
            if (!empty($result)) {
                $user = $result;
                if (password_verify($user_data['password'], $user['password'])) {
                    $token = Token::generate_token($user['id_usuario']); // -> generamos el token aqui en base al id_usuario
                } else {
                    throw new Exception('Credenciales invalidas');
                }
            } else {
                throw new Exception('Usuario inexistente');
            }
            return [
                'token' => $token,
                'id_usuario' => $user['id_usuario']
            ];
        } catch (Exception $ex) {
            throw new Exception($ex->getMessage());
        }
    }


```

#### Ejemplo de validacion de token en middleware personalizado

```php
<?php

namespace app\Middlewares;

use gabogalro\Token\Token;
use app\Middlewares\Middlewares;
use Exception;
use gabogalro\responseHelpers\Response;

class AuthMiddleware implements Middlewares
{
    /**
     * Summary of handle
     * @param mixed $requestHeaders
     * @param mixed $next
     */
    public static function handle($requestHeaders, $next)
    {
        try {
            if (!isset($requestHeaders['Authorization'])) {
                throw new Exception('Forbbiden');
            }

            $authHeader = $requestHeaders['Authorization'];

            if (preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
                $token = $matches[1];

                if (Token::validate_token($token)) {
                    return $next(); // si el token es valido da acceso
                }
            }
        } catch (Exception $ex) {
            echo Response::error('Error', $ex->getMessage(), 403);
        }
    }
}

```

#### Ejemplo de invalidacion de token

```php
 public function logout($token)
    {
        Token::invalidate_token($token); //-> esto destruye la sesion activa del token de forma logica
    }
```

## Requisitos previos

- PHP 7.4 o superior
- Composer

## License

MIT © gabogalro. See [LICENSE](LICENSE) for details.
