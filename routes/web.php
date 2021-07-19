<?php

/** @var \Laravel\Lumen\Routing\Router $router */

/*
|--------------------------------------------------------------------------
| Application Routes
|--------------------------------------------------------------------------
|
| Here is where you can register all of the routes for an application.
| It is a breeze. Simply tell Lumen the URIs it should respond to
| and give it the Closure to call when that URI is requested.
|
*/

$router->get('/', function () use ($router) {
    return $router->app->version();
});

$router->group(['prefix' => 'auth'], function () use ($router) {
    $router->post('register', 'AuthController@register');

    $router->post('login', 'AuthController@login');

    $router->post('logout', 'AuthController@logout');

    $router->post('refresh', 'AuthController@refresh');

    $router->get('/confirm/registration/{token}', 'AuthController@confirmRegistration');

    $router->get('/password/reset/{username}', 'AuthController@sendPasswordReset');

    $router->post('/change/password', 'AuthController@changePassword');
});