<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Custom Configuration Values
    |--------------------------------------------------------------------------
    |
    | Here you may specify all custom configuration values of application.
    |
    */

    'url' => env('APP_URL'),

    'key' => env('APP_KEY'),

    'cipher' => env('CIPHER', 'AES-256-CBC'),

    'env' => env('APP_ENV'),

    'ttl' => env('JWT_TTL', 60),

    'registration_url' => env('REGISTRATION_URL'),

    'reset_password_url' => env('RESET_PASSWORD_URL'),
];
