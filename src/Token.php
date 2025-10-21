<?php

namespace gabogalro\Token;

use gabogalro\SQLHelpers\DB;
use Exception;

class Token
{

    public static function generate_token($id_usuario)
    {
        try {
            $token = bin2hex(random_bytes(64));
            $hashed_token = password_hash($token, PASSWORD_BCRYPT);
            $expire_time = date('Y-m-d H:i:s', strtotime('+12 hour'));


            $fingerprint = hash('sha256', $_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT']);
            $result = DB::selectAll("call sp_generate_token(?, ?, ?, ?)", [
                $id_usuario,
                $hashed_token,
                $fingerprint,
                $expire_time
            ]);
            $token_id = $result[0]['id_token'];
            $final_token = strval($token_id) . '|' . $token;
            return $final_token;
        } catch (Exception $ex) {
            throw new Exception($ex->getMessage());
        }
    }

    public static function invalidate_token($token)
    {
        try {
            if (strpos($token, '|') === false) {
                throw new Exception('Forbbiden');
            }

            [$id_token] = explode('|', $token, 2);

            $result = DB::selectOne("SELECT id_usuario, fingerprint, is_active FROM tokens WHERE id_token = ?", [$id_token]);

            if (!$result || !$result['is_active']) {
                throw new Exception('Forbbiden');
            }
            DB::statement("UPDATE tokens SET is_active = 0 WHERE id_token = ?", [$id_token]);
            return true;
        } catch (Exception $ex) {
            throw new Exception($ex->getMessage());
        }
    }

    public static function validate_token($token)
    {

        try {
            if (strpos($token, '|') === false) {
                throw new Exception('Forbbiden');
            }

            [$id_token, $token_plain] = explode('|', $token, 2);

            $result = DB::selectOne("call sp_validate_token(?)", $id_token);
            if (empty($result)) {
                throw new Exception('Forbbiden');
            }
            $current_fingerprint = hash('sha256', $_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT']);

            if ($result['fingerprint'] !== $current_fingerprint) {
                Token::invalidate_token($token);
                throw new Exception('Forbbiden');
            }

            if (password_verify($token_plain, $result['token'])) {
                return true;
            } else {
                throw new Exception('Forbbiden');
            }
        } catch (Exception $ex) {
            throw new Exception($ex->getMessage());
        }
    }
}
