<?php

namespace gabogalro\AuthMiddleware;

use gabogalro\Token\Token;
use gabogalro\Middleware\Middleware;

class AuthMiddleware implements Middleware
{
    /**
     * Summary of handle
     * @param mixed $requestHeaders
     * @param mixed $next
     */
    public static function handle($requestHeaders, $next)
    {
        if (!isset($requestHeaders['Authorization'])) {
            http_response_code(401);
            echo json_encode(['error' => 'Unauthorized: Token missing']);
            exit;
        }

        $authHeader = $requestHeaders['Authorization'];

        if (preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
            $token = $matches[1];

            if (Token::validate_token($token)) {
                return $next();
            } else {
                http_response_code(403);
                echo json_encode(['error' => 'Forbidden: Invalid or expired token']);
                exit;
            }
        } else {
            http_response_code(400);
            echo json_encode(['error' => 'Bad Request: Malformed Authorization header']);
            exit;
        }
    }
}
