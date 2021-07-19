<?php

use App\Helpers\HttpStatus as Status;
use Laravel\Lumen\Testing\TestCase as BaseTestCase;

abstract class TestCase extends BaseTestCase
{
    /**
     * Mandatory HTTP headers.
     *
     * @var array
     */
    protected $headers;

    /**
     * Setup the test environment.
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->baseUrl = config('app.url');
    }

    /**
     * Creates the application.
     *
     * @return \Laravel\Lumen\Application
     */
    public function createApplication()
    {
        return require __DIR__ . '/../bootstrap/app.php';
    }

    /**
     * Set mandatory HTTP headers.
     *
     * @param  array  $payload
     * @return void
     */
    protected function loginUser(array $payload): void
    {
        $token = $this->post('auth/login', $payload)
                      ->seeStatusCode(Status::OK)
                      ->response
                      ->decodeResponseJson()['data']['token'];

        $this->headers = [
            'Content-Type' => 'application/x-www-form-urlencoded',
            'Authorization-token' => 'Bearer ' . $token,
        ];
    }
}
