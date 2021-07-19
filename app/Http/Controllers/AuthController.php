<?php

namespace App\Http\Controllers;

use Log;
use Throwable;
use App\Models\User;
use App\Mail\ResetPassword;
use Illuminate\Http\Request;
use App\Models\PasswordReset;
use Illuminate\Http\JsonResponse;
use App\Http\Requests\UserRequest;
use App\Mail\RegisterConfirmation;
use Illuminate\Support\Facades\Mail;
use App\Helpers\HttpStatus as Status;
use Illuminate\Database\QueryException;
use App\Exceptions\DuplicateEntryException;

class AuthController extends Controller
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
     * Create a new controller instance.
     *
     * @param \App\Models\User  $user
     * @param \App\Models\PasswordReset  $passwordReset
     */
    public function __construct(User $user, PasswordReset $passwordReset)
    {
        $this->middleware('auth:api', ['only' => ['logout', 'refresh']]);

        $this->user = $user;

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
            $userData = $request->only(['username', 'name']) + ['token' => $this->user->new($request)->email_verification_token];

            Mail::to($request->username)->send(new RegisterConfirmation($userData));

            Log::info(self::MESSAGES['REGISTER.SUCCESS'] . ' : ' . $request->username);

            return response()->api([
                'status' => Status::CREATED,
                'message' => self::MESSAGES['REGISTER.SUCCESS'],
            ]);
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
            Log::info(self::MESSAGES['LOGOUT.SUCCESS'] . ' : ' . auth()->user()->username);

            auth()->logout();

            return response()->api([
                'status' => Status::OK,
                'message' => self::MESSAGES['LOGOUT.SUCCESS'],
            ]);
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
            return $this->createNewToken(auth()->refresh());
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
            if (!empty($request->username) && $user = $this->user->fetch($request->username)->first()) {
                if ($user->email_verified) {
                    if ($this->passwordReset->getToken($request)->first()) {
                        Log::error(self::MESSAGES['RESET.ERROR'] . ' : ' . $request->username);

                        return response()->api([
                            'status' => Status::BAD_REQUEST,
                            'message' => self::MESSAGES['RESET.ERROR'],
                        ]);
                    } else {
                        $passwordReset = $this->passwordReset->createToken($request);

                        $userData = $user->only(['username', 'name']) + ['token' => $passwordReset->token];

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
            if (!empty($request->token)) {
                $tokenData = $this->passwordReset->getUsername($request)->first();

                if (!empty($tokenData)) {
                    $user = $this->user->fetch($tokenData->username)->first();

                    if (!empty($user)) {
                        $user->update([
                            'password' => $request->password,
                        ]);

                        $this->passwordReset->deleteToken($user);

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
        } catch (Throwable $t) {
            $this->logError($t);
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
