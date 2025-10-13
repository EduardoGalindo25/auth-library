<?php

namespace gabogalro\Middleware;

interface Middleware
{
    public static function handle($requestHeaders, $next);
}
