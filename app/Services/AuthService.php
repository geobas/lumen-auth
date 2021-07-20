<?php

namespace App\Services;

use Log;
use App\Models\User;
use App\Mail\ResetPassword;
use Illuminate\Http\Request;
use App\Models\PasswordReset;
use Illuminate\Http\JsonResponse;
use App\Mail\RegisterConfirmation;
use Illuminate\Support\Facades\Mail;
use App\Helpers\HttpStatus as Status;

class AuthService
{
    /**
     * Authentication messages.
     *
     * @var array
     */
    const MESSAGES = [
        'REGISTER.SUCCESS' => 'User was registered successfully.',
        'LOGIN.SUCCESS' => 'User logged in successfully.',
        'LOGIN.UNAUTHORIZED' => 'Unauthorized.',
        'LOGIN.NOTACTIVATED' => 'Account is not yet activated.',
        'LOGIN.UNKNOWN' => 'Unknown user.',
        'LOGOUT.SUCCESS' => 'User successfully signed out.',
        'CONFIRM.SUCCESS' => 'Account activated.',
        'CONFIRM.ERROR' => 'Invalid token.',
        'RESET.ERROR' => 'Password reset email has been already sent.',
        'RESET.SUCCESS' => 'Password reset email was sent successfully.',
        'CHANGE.SUCCESS' => 'Password was changed successfully.',
        'CHANGE.UNKNOWN' => 'Unknown token.',
        'CHANGE.MISSING' => 'Reset token is missing.',
    ];

    /**
     * Instance of logged-in User.
     *
     * @var \App\Models\User
     */
    public $user;

    /**
     * Create a new service instance.
     *
     * @param \App\Models\User  $user
     */
    public function __construct(User $user)
    {
        $this->user = $user;
    }

    /**
     * Register a new user.
     * 
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function register(Request $request): JsonResponse
    {
        $userData = $request->only(['username', 'name']) + ['token' => $this->user->new($request)->email_verification_token];

        Mail::to($request->username)->send(new RegisterConfirmation($userData));

        Log::info(self::MESSAGES['REGISTER.SUCCESS'] . ' : ' . $request->username);

        return response()->api([
            'status' => Status::CREATED,
            'message' => self::MESSAGES['REGISTER.SUCCESS'],
        ]);
    }

    /**
     * Login a user.
     * 
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request): JsonResponse
    {
        if ($user = $this->user->fetch($request->username)->first()) {
            if ($user->email_verified) {
                $credentials = $request->only(['username', 'password']);

                if (!$token = auth()->attempt($credentials)) {
                    Log::error(self::MESSAGES['LOGIN.UNAUTHORIZED'] . ' : ' . $request->username);

                    return response()->api([
                        'status' => Status::UNAUTHORIZED,
                        'message' => self::MESSAGES['LOGIN.UNAUTHORIZED'],
                    ]);
                }

                Log::info(self::MESSAGES['LOGIN.SUCCESS'] . ' : ' . $request->username);

                return $this->createNewToken($token);
            } else {
                Log::warning(self::MESSAGES['LOGIN.NOTACTIVATED'] . ' : ' . $request->username);

                return response()->api([
                    'status' => Status::UNAUTHORIZED,
                    'message' => self::MESSAGES['LOGIN.NOTACTIVATED'],
                ]);
            }
        } else {
            Log::error(self::MESSAGES['LOGIN.UNKNOWN'] . ' : ' . $request->username);

            return response()->api([
                'status' => Status::BAD_REQUEST,
                'message' => self::MESSAGES['LOGIN.UNKNOWN'],
            ]);
        }
    }

    /**
     * Logout a user.
     * 
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout(): JsonResponse
    {
        Log::info(self::MESSAGES['LOGOUT.SUCCESS'] . ' : ' . auth()->user()->username);
        
        auth()->logout();

        return response()->api([
            'status' => Status::OK,
            'message' => self::MESSAGES['LOGOUT.SUCCESS'],
        ]);
    }

    /**
     * Refresh a token.
     * 
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh(): JsonResponse
    {
        return $this->createNewToken(auth()->refresh());
    }

    /**
     * Confirm registration of a User.
     * 
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function confirmRegistration(Request $request): JsonResponse
    {
        if (!empty($request->token)) {
            $user = $this->user->fetch($request->token)->first();

            if (!empty($user)) {
                $user->confirmRegistration();

                Log::info(self::MESSAGES['CONFIRM.SUCCESS'] . ' : ' . $user->username);

                return response()->api([
                    'status' => Status::OK,
                    'message' => self::MESSAGES['CONFIRM.SUCCESS'],
                ]);
            } else {
                Log::error(self::MESSAGES['CONFIRM.ERROR'] . ' : ' . $request->token);

                return response()->api([
                    'status' => Status::BAD_REQUEST,
                    'message' => self::MESSAGES['CONFIRM.ERROR'],
                ]);
            }
        }
    }

    /**
     * Send an email with reset password details.
     * 
     * @param  \Illuminate\Http\Request  $request
     * @param  \App\Models\PasswordReset  $passwordReset
     * @return \Illuminate\Http\JsonResponse
     */
    public function sendPasswordReset(Request $request, PasswordReset $passwordReset): JsonResponse
    {
        if (!empty($request->username) && $user = $this->user->fetch($request->username)->first()) {
            if ($user->email_verified) {
                if ($passwordReset->getToken($request)->first()) {
                    Log::error(self::MESSAGES['RESET.ERROR'] . ' : ' . $request->username);

                    return response()->api([
                        'status' => Status::BAD_REQUEST,
                        'message' => self::MESSAGES['RESET.ERROR'],
                    ]);
                } else {
                    $passwordResetObj = $passwordReset->createToken($request);

                    $userData = $user->only(['username', 'name']) + ['token' => $passwordResetObj->token];

                    Mail::to($request->username)->send(new ResetPassword($userData));

                    Log::info(self::MESSAGES['RESET.SUCCESS'] . ' : ' . $request->username);

                    return response()->api([
                        'status' => Status::OK,
                        'message' => self::MESSAGES['RESET.SUCCESS'],
                    ]);
                }
            } else {
                Log::warning(self::MESSAGES['LOGIN.NOTACTIVATED'] . ' : ' . $request->username);

                return response()->api([
                    'status' => Status::BAD_REQUEST,
                    'message' => self::MESSAGES['LOGIN.NOTACTIVATED'],
                ]);
            }
        } else {
            Log::error(self::MESSAGES['LOGIN.UNKNOWN'] . ' : ' . $request->username);

            return response()->api([
                'status' => Status::BAD_REQUEST,
                'message' => self::MESSAGES['LOGIN.UNKNOWN'],
            ]);
        }
    }

    /**
     * Change User password.
     * 
     * @param  \Illuminate\Http\Request  $request
     * @param  \App\Models\PasswordReset  $passwordReset
     * @return \Illuminate\Http\JsonResponse
     */
    public function changePassword(Request $request, PasswordReset $passwordReset): JsonResponse
    {
        if (!empty($request->token)) {
            $tokenData = $passwordReset->getUsername($request)->first();

            if (!empty($tokenData)) {
                $user = $this->user->fetch($tokenData->username)->first();

                if (!empty($user)) {
                    $user->update([
                        'password' => $request->password,
                    ]);

                    $passwordReset->deleteToken($user);

                    Log::info(self::MESSAGES['CHANGE.SUCCESS'] . ' : ' . $user->username);

                    return response()->api([
                        'status' => Status::OK,
                        'message' => self::MESSAGES['CHANGE.SUCCESS'],
                    ]);
                } else {
                    Log::error(self::MESSAGES['LOGIN.UNKNOWN'] . ' : ' . $request->token);

                    return response()->api([
                        'status' => Status::NOT_FOUND,
                        'message' => self::MESSAGES['LOGIN.UNKNOWN'],
                    ]);
                }
            } else {
                Log::error(self::MESSAGES['CHANGE.UNKNOWN'] . ' : ' . $request->token);

                return response()->api([
                    'status' => Status::BAD_REQUEST,
                    'message' => self::MESSAGES['CHANGE.UNKNOWN'],
                ]);
            }
        } else {
            Log::error(self::MESSAGES['CHANGE.MISSING']);

            return response()->api([
                'status' => Status::BAD_REQUEST,
                'message' => self::MESSAGES['CHANGE.MISSING'],
            ]);
        }
    }

    /**
     * Get the token array structure.
     *
     * @param  string  $token
     * @return \Illuminate\Http\JsonResponse
     */
    private function createNewToken(string $token): JsonResponse
    {
        $data = [
            'token' => $token,
            'token_type' => 'bearer',
            'expires_in' => (int) config('app.ttl'),
        ];

        $response = response()->api([
            'status' => Status::OK,
            'data' => $data + $this->getUserInfo(),
        ]);

        return $response;
    }

    /**
     * Get additional info for logged-in User.
     *
     * @return array
     */
    private function getUserInfo(): array
    {
        $userId = [
            'user_id' => auth()->user()->id,
            'name' => auth()->user()->name,
        ];

        return $userId;
    }        
}
