<?php

namespace App\Http\Controllers;

use Log;
use Throwable;
use App\Mail\ResetPassword;
use Illuminate\Http\Request;
use App\Models\PasswordReset;
use App\Services\AuthService;
use Illuminate\Http\JsonResponse;
use App\Http\Requests\UserRequest;
use Illuminate\Database\QueryException;
use App\Exceptions\DuplicateEntryException;

class AuthController extends Controller
{
    /**
     * Create a new controller instance.
     *
     * @param \App\Services\AuthService  $service
     * @param \App\Models\PasswordReset  $passwordReset
     */
    public function __construct(AuthService $service, PasswordReset $passwordReset)
    {
        $this->middleware('auth:api', ['only' => ['logout', 'refresh']]);

        $this->service = $service;

        $this->passwordReset = $passwordReset;
    }

    /**
     * Register a User.
     *
     * @param  \App\Http\Requests\UserRequest  $request
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \App\Exceptions\DuplicateEntryException
     */
    public function register(UserRequest $request): JsonResponse
    {
        try {
            return $this->service->register($request);
        } catch (QueryException $e) {
            throw new DuplicateEntryException($this->formatErrorMessage($e));
        } catch (Throwable $t) {
            $this->logError($t);
        }
    }

    /**
     * Log the User in the system.
     *
     * @param  \App\Http\Requests\UserRequest  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(UserRequest $request): JsonResponse
    {
        try {
            return $this->service->login($request);
        } catch (Throwable $t) {
            $this->logError($t);
        }
    }

    /**
     * Log the User out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout(): JsonResponse
    {
        try {
            return $this->service->logout();
        } catch (Throwable $t) {
            $this->logError($t);
        }
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Tymon\JWTAuth\Exceptions\TokenBlacklistedException
     */
    public function refresh(): JsonResponse
    {
        try {
            return $this->service->refresh();
        } catch (Throwable $t) {
            $this->logError($t);
        }
    }

    /**
     * Confirm registration of a User.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function confirmRegistration(Request $request): JsonResponse
    {
        try {
            return $this->service->confirmRegistration($request);
        } catch (Throwable $t) {
            $this->logError($t);
        }
    }

    /**
     * Send an email with reset password details.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function sendPasswordReset(Request $request): JsonResponse
    {
        try {
            return $this->service->sendPasswordReset($request, $this->passwordReset);
        } catch (Throwable $t) {
            $this->logError($t);
        }
    }

    /**
     * Change a User's password.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function changePassword(UserRequest $request): JsonResponse
    {
        try {
            return $this->service->changePassword($request, $this->passwordReset);
        } catch (Throwable $t) {
            $this->logError($t);
        }
    }

    /**
     * Format the error message for a duplicate entry.
     *
     * @param  \Illuminate\Database\QueryException  $e
     * @return string
     */
    private function formatErrorMessage(QueryException $e): string
    {
        if (!empty($e->errorInfo)) {
            $message = explode(' for', $e->errorInfo[2])[0];
        } else {
            $message = $e->getMessage();
        }

        return $message;
    }
}
