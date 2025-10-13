<?php

namespace gabogalro\Token;

use gabogalro\SQLHelpers\DB;
use Exception;

class Token
{
    /**
     * Generate a secure token, store its hash in the database with expiration
     * and return the plain token.
     * @param int $user_id ID of the user the token is for
     * @param int $expiration Expiration time in hours (default 12)
     * @return string The generated token
     * @throws Exception If the database driver is not supported
     */

    public static function generate_token($user_id, $expiration = 12)
    {

        $token = bin2hex(random_bytes(64));
        $hashed_token = password_hash($token, PASSWORD_BCRYPT);
        $create_time = date('Y-m-d H:i:s');
        $expire_time = date('Y-m-d H:i:s', strtotime("+$expiration hours"));

        $DB_DRIVER = $_ENV['DB_DRIVER'] ?? null;
        switch (strtolower($DB_DRIVER)) {
            case 'mysql':
                $result = DB::selectOne("insert into tokens(user_id, token, created_at, expires_at, is_active) values(?, ?, ?, ?, ?)", [
                    $user_id,
                    $hashed_token,
                    $create_time,
                    $expire_time,
                    1
                ]);
                $token_id = $result[0][0];
                break;
            case 'sqlsrv':
                $result = DB::selectOne("insert into tokens(id_usuario, token, created_at, expires_at, is_active) values ?, ?, ?, ?, ?", [
                    $user_id,
                    $hashed_token,
                    $create_time,
                    $expire_time,
                    1
                ]);
                $token_id = $result;
                break;
            default:
                throw new Exception("Driver not supported: $DB_DRIVER");
        }
        $final_token = strval($token_id) . '|' . $token;
        return $final_token;
    }

    /**
     * Validate a given token against stored hashes and check expiration
     * Summary of validate_token
     * @param mixed $token
     * @throws Exception
     * @return bool
     */
    public static function validate_token($token)
    {
        $DB_DRIVER = $_ENV['DB_DRIVER'] ?? null;

        if (strpos($token, '|') === false) {
            return false;
        }

        [$token_id, $token_plain] = explode('|', $token, 2);

        switch (strtolower($DB_DRIVER)) {
            case 'mysql':
                $result = DB::selectOne("SELECT token, expires_at, is_active FROM tokens WHERE token_id = ?", [$token_id]);
                if (empty($result[0])) {
                    return false;
                }
                $record = $result[0][0];

                if ($record->is_active != 1 || strtotime($record->expires_at) < time()) {
                    return false;
                }

                return password_verify($token_plain, $record->token);

            case 'sqlsrv':
                $result = DB::selectOne("SELECT token, expires_at, is_active FROM tokens WHERE token_id = ?", [$token_id]);
                if (empty($result)) {
                    return false;
                }
                $record = $result[0];

                if ($record->is_active != 1 || strtotime($record->expires_at) < time()) {
                    return false;
                }

                return password_verify($token_plain, $record->token);

            default:
                throw new Exception("Driver not supported: $DB_DRIVER");
        }
    }


    /**
     * Invalidate a token by setting its is_active flag to false
     * @param mixed $token
     */

    public static function invalidate_token($token)
    {
        $DB_DRIVER = $_ENV['DB_DRIVER'] ?? null;

        if (strpos($token, '|') === false) {
            return false;
        }

        [$token_id, $token_plain] = explode('|', $token, 2);

        switch (strtolower($DB_DRIVER)) {
            case 'mysql':
                $result = DB::selectOne("SELECT token, is_active FROM tokens WHERE token_id = ?", [$token_id]);
                if (empty($result[0])) {
                    return false;
                }
                $record = $result[0][0];

                if ($record->is_active != 1 || !password_verify($token_plain, $record->token)) {
                    return false;
                }

                DB::statement("UPDATE tokens SET is_active = 0 WHERE token_id = ?", [$token_id]);
                return true;

            case 'sqlsrv':
                $result = DB::selectOne("SELECT token, is_active FROM tokens WHERE token_id = ?", [$token_id]);
                if (empty($result)) {
                    return false;
                }
                $record = $result[0];

                if ($record->is_active != 1 || !password_verify($token_plain, $record->token)) {
                    return false;
                }

                DB::statement("UPDATE tokens SET is_active = 0 WHERE token_id = ?", [$token_id]);
                return true;

            default:
                throw new Exception("Driver not supported: $DB_DRIVER");
        }
    }
}
