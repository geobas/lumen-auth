<?php

use App\Models\User;
use App\Mail\ResetPassword;
use App\Models\PasswordReset;
use App\Services\AuthService;
use App\Http\Requests\UserRequest;
use App\Mail\RegisterConfirmation;
use Illuminate\Support\Facades\Mail;
use App\Helpers\HttpStatus as Status;
use Tymon\JWTAuth\Exceptions\TokenBlacklistedException;

class AuthenticationTest extends TestCase
{
    /**
     * User dummy data.
     *
     * @var array
     */
    private $payload = [
        'username' => 'takis@testakis.com',
        'password' => '123456',
        'password_confirmation' => '123456',
        'name' => 'takis testakis',
    ];

    public static function tearDownAfterClass(): void
    {
        (new self())->setUp();

        User::where('username', 'takis@testakis.com')->delete();
    }

    protected function setUp(): void
    {
        parent::setUp();

        Mail::fake();
    }

    /**
     * @test
     */
    public function register_a_new_user()
    {
        $this->post('auth/register', $this->payload)
             ->seeStatusCode(Status::OK)
             ->seeJsonStructure([
                'status',
                'message'
             ])
             ->seeJson([
             	'status' => Status::CREATED,
             ])
             ->seeJson([
             	'message' => AuthService::MESSAGES['REGISTER.SUCCESS'],
             ]);

        Mail::assertSent(RegisterConfirmation::class, function ($mail) {
            return $mail->hasTo($this->payload['username']) &&
                   $mail->userData->name == $this->payload['name'];
        });

        $this->post('auth/register', $this->payload)
             ->seeStatusCode(Status::OK)
             ->seeJson([
                'status' => Status::BAD_REQUEST,
                'error' => $this->formatErrorMessage('username.unique'),
             ]);

        $this->post('auth/login', $this->payload)
             ->seeStatusCode(Status::OK)
             ->seeJson([
                'status' => Status::UNAUTHORIZED,
                'message' => AuthService::MESSAGES['LOGIN.NOTACTIVATED'],
             ]);
    }

    /**
     * @test
     */
    public function confirm_registration_of_new_user()
    {
        $user = User::latest()->first();

        $this->get('/auth/confirm/registration/' . $user->email_verification_token)
             ->seeStatusCode(Status::OK)
             ->seeJsonStructure([
                'status',
                'message'
             ])
             ->seeJson([
                'message' => AuthService::MESSAGES['CONFIRM.SUCCESS'],
             ]);

        Mail::assertNothingSent();

        $user->refresh();

        $this->assertEquals(1, $user->email_verified);

        $this->assertEmpty($user->email_verification_token);

        $this->get('/auth/confirm/registration/el2Sn3fjibPI4G8k30eFnFfXthBIY7APlRuvsctHnNHdtJuHsFNLHcfi0BiTjI6Y')
             ->seeStatusCode(Status::OK)
             ->seeJson([
                'message' => AuthService::MESSAGES['CONFIRM.ERROR'],
             ]);
    }

    /**
     * @test
     */
    public function login_user()
    {
        $this->post('auth/login', $this->payload)
             ->seeStatusCode(Status::OK)
             ->seeJsonStructure([
                'status',
                'data' => [
                    'token',
                    'token_type',
                    'expires_in',
                    'user_id',
                    'name',
                ],
             ])
             ->seeJson([
                'token_type' => 'bearer',
                'expires_in' => 60,
                'user_id' => User::latest()->first()->id,
                'name' => User::latest()->first()->name,
             ]);

        Mail::assertNothingSent();

        $this->post('auth/login')
             ->seeStatusCode(Status::OK)
             ->seeJson([
                'status' => Status::BAD_REQUEST,
                'error' => $this->formatErrorMessage('username.required') . ', ' . $this->formatErrorMessage('password.required'),
             ]);
    }

    /**
     * @test
     */
    public function logout_user()
    {
        $this->loginUser($this->payload);

        $this->post('auth/logout', [], $this->headers)
             ->seeStatusCode(Status::OK)
             ->seeJsonStructure([
                'status',
                'message',
             ])
             ->seeJson([
                'message' => AuthService::MESSAGES['LOGOUT.SUCCESS'],
             ]);

        Mail::assertNothingSent();

        $this->post('auth/logout', [])
             ->seeStatusCode(Status::OK)
             ->seeJson([
                'status' => Status::UNAUTHORIZED,
                'message' => AuthService::MESSAGES['LOGIN.UNAUTHORIZED'],
             ]);
    }

    /**
     * @test
     */
    public function refresh_token()
    {
        $this->loginUser($this->payload);

        $this->post('auth/refresh', [], $this->headers)
             ->seeStatusCode(Status::OK)
             ->seeJsonStructure([
                'status',
                'data' => [
                    'token',
                    'token_type',
                    'expires_in',
                    'user_id',
                    'name',
                ],
             ])
             ->seeJson([
                'token_type' => 'bearer',
                'expires_in' => 60,
                'user_id' => User::latest()->first()->id,
                'name' => User::latest()->first()->name,
             ]);

        Mail::assertNothingSent();

        $this->expectException(TokenBlacklistedException::class);

        $this->expectExceptionMessage('The token has been blacklisted');

        $this->post('auth/refresh', [])
             ->seeStatusCode(Status::INTERNAL_SERVER_ERROR)
             ->seeJson([
                'status' => Status::UNAUTHORIZED,
                'message' => AuthService::MESSAGES['LOGIN.UNAUTHORIZED'],
             ]);
    }

    /**
     * @test
     */
    public function password_reset_notification()
    {
        $user = User::latest()->first();

        $this->get('/auth/password/reset/' . $user->username)
             ->seeStatusCode(Status::OK)
             ->seeJsonStructure([
                'status',
                'message',
             ])
             ->seeJson([
                'message' => AuthService::MESSAGES['RESET.SUCCESS'],
             ]);

        Mail::assertSent(ResetPassword::class, function ($mail) {
            return $mail->hasTo($this->payload['username']) &&
                   $mail->userData->name == $this->payload['name'];
        });

        $passwordReset = PasswordReset::latest()->first();

        $this->assertEquals($this->payload['username'], $passwordReset->username);

        $this->get('/auth/password/reset/' . $user->username)
             ->seeStatusCode(Status::OK)
             ->seeJson([
                'message' => AuthService::MESSAGES['RESET.ERROR'],
             ]);

        $this->get('/auth/password/reset/unknown@test.gr')
             ->seeStatusCode(Status::OK)
             ->seeJson([
                'message' => AuthService::MESSAGES['LOGIN.UNKNOWN'],
             ]);
    }

    /**
     * @test
     */
    public function change_user_password()
    {
        $passwordReset = PasswordReset::latest()->first();

        $this->post('/auth/change/password', ['password' => 12345, 'password_confirmation' => 12345, 'token' => $passwordReset->token])
             ->seeStatusCode(Status::OK)
             ->seeJsonStructure([
                'status',
                'message',
             ])
             ->seeJson([
                'message' => AuthService::MESSAGES['CHANGE.SUCCESS'],
             ]);

        Mail::assertNothingSent();

        $this->assertNull(PasswordReset::where('username', $passwordReset->username)->first());

        $this->post('auth/login', ['username' => $this->payload['username'], 'password' => 12345])
             ->seeStatusCode(Status::OK)
             ->seeJsonStructure([
                'status',
                'data' => [
                    'token',
                    'token_type',
                    'expires_in',
                    'user_id',
                    'name',
                ],
             ])
             ->seeJson([
                'token_type' => 'bearer',
                'expires_in' => 60,
             ]);

        $this->post('/auth/change/password')
             ->seeStatusCode(Status::OK)
             ->seeJson([
                'error' => $this->formatErrorMessage('password.required') . ', ' . $this->formatErrorMessage('token.required'),
             ]);

        $this->post('/auth/change/password', ['password' => 12345, 'password_confirmation' => 12345, 'token' => $passwordReset->token])
             ->seeStatusCode(Status::OK)
             ->seeJson([
                'message' => AuthService::MESSAGES['CHANGE.UNKNOWN'],
             ]);

        $this->post('/auth/change/password', ['password' => 12345, 'token' => $passwordReset->token])
             ->seeStatusCode(Status::OK)
             ->seeJson([
                'status' => Status::BAD_REQUEST,
                'error' => 'password confirmation does not match',
             ]);
    }

    /**
     * Format a validation error message.
     *
     * @param  string  $rule
     * @return string
     */
    private function formatErrorMessage(string $rule): string
    {
        return str_replace(':attribute', explode('.', $rule)[0], (new UserRequest)->messages()[$rule]);
    }
}
