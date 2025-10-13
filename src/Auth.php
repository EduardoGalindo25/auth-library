<?php

namespace gabogalro\Auth;

use gabogalro\SQLHelpers\DB;
use Exception;
use gabogalro\Token\Token;

class Auth
{

    public static function login($username, $password)
    {
        $DB_DRIVER = $_ENV['DB_DRIVER'] ?? null;
        switch (strtolower($DB_DRIVER)) {
            case 'mysql':
                $result = DB::selectAll("SELECT * FROM users WHERE username = ? AND is_active = 1", [$username]);
                if (!empty($result[0])) {
                    $user = $result[0][0];
                    if (password_verify($password, $user->password)) {
                        return Token::generate_token($user->user_id);
                    }
                }
                return false;

            case 'sqlsrv':
                $result = DB::selectAll("SELECT * FROM users WHERE username = ? AND is_active = 1", [$username]);
                if (!empty($result)) {
                    $user = $result[0];
                    if (password_verify($password, $user->password)) {
                        return Token::generate_token($user->user_id);
                    }
                }
                return false;
        }
    }

    public static function logout($token)
    {
        return Token::invalidate_token($token);
    }

    public static function register_user($user, $email = null, $password)
    {

        $DB_DRIVER = $_ENV['DB_DRIVER'] ?? null;
        switch (strtolower($DB_DRIVER)) {
            case 'mysql':
                $users = DB::selectAll("select * from users where username = ? or email = ?", [
                    $user,
                    $email
                ]);
                if (count($users[0]) > 0) {
                    throw new Exception("User or email already exists");
                } else {
                    $hashed_password = password_hash($password, PASSWORD_BCRYPT);
                    $datetime = date('Y-m-d H:i:s');
                    DB::statement("insert into users(username, email, password, created_at, is_active) values(?, ?, ?, ?, ?)", [
                        $user,
                        $email,
                        $hashed_password,
                        $datetime,
                        1
                    ]);
                }
                break;
            case 'sqlsrv':
                $users = DB::selectAll("select * from users where username = ? or email = ?", [
                    $user,
                    $email
                ]);
                if (count($users) > 0) {
                    throw new Exception("User or email already exists");
                } else {
                    $hashed_password = password_hash($password, PASSWORD_BCRYPT);
                    $datetime = date('Y-m-d H:i:s');
                    DB::statement("insert into users(username, email, password, created_at, is_active) values (?, ?, ?, ?, ?)", [
                        $user,
                        $email,
                        $hashed_password,
                        $datetime,
                        1
                    ]);
                }
                break;
            default:
                throw new Exception("Driver not supported: $DB_DRIVER");
        }

        return;
    }
}
