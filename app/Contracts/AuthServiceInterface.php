<?php

namespace App\Contracts;

use Illuminate\Http\Request;
use App\Models\PasswordReset;
use Illuminate\Http\JsonResponse;

interface AuthServiceInterface
{
    /**
     * Register a new user.
     * 
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */ 
    public function register(Request $request): JsonResponse;

    /**
     * Login a user.
     * 
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request): JsonResponse;

    /**
     * Logout a user.
     * 
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout(): JsonResponse;

    /**
     * Refresh a token.
     * 
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh(): JsonResponse;

    /**
     * Confirm registration of a User.
     * 
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function confirmRegistration(Request $request): JsonResponse;

    /**
     * Send an email with reset password details.
     * 
     * @param  \Illuminate\Http\Request  $request
     * @param  \App\Models\PasswordReset  $passwordReset
     * @return \Illuminate\Http\JsonResponse
     */
    public function sendPasswordReset(Request $request, PasswordReset $passwordReset): JsonResponse;

    /**
     * Change User password.
     * 
     * @param  \Illuminate\Http\Request  $request
     * @param  \App\Models\PasswordReset  $passwordReset
     * @return \Illuminate\Http\JsonResponse
     */
    public function changePassword(Request $request, PasswordReset $passwordReset): JsonResponse;
}