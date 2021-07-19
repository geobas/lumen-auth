<?php

namespace App\Http\Middleware;

use Log;
use Closure;
use App\Helpers\HttpStatus as Status;
use Illuminate\Contracts\Auth\Factory as Auth;

class Authenticate
{
    /**
     * The authentication guard factory instance.
     *
     * @var \Illuminate\Contracts\Auth\Factory
     */
    protected $auth;

    /**
     * Create a new middleware instance.
     *
     * @param  \Illuminate\Contracts\Auth\Factory  $auth
     * @return void
     */
    public function __construct(Auth $auth)
    {
        $this->auth = $auth;
    }

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @param  string|null  $guard
     * @return mixed
     */
    public function handle($request, Closure $next, $guard = null)
    {
        app()->request->headers->set('Authorization', app()->request->header('Authorization-token'));

        if ($this->auth->guard($guard)->guest()) {
            Log::info('Unauthorized access attempt from: ' . $request->ip());

            return response()->api([
                'status' => Status::UNAUTHORIZED,
                'message' => 'Unauthorized.',
            ]);
        }

        return $next($request);
    }
}
