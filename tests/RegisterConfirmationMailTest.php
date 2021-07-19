<?php

use App\Mail\RegisterConfirmation;

class RegisterConfirmationMailTest extends TestCase
{
    /**
     * @test
     */
    public function register_confirmation_mailable_content()
    {
        $userData = [
            'username' => 'dummy@user.com',
            'name' => 'John Doe',
            'token' => 'IbXiMcIV9SNDRNn9iPfyss5KK4xko262cFUoQRmGprc2mi7u4sY2pzRN6NmrMuJM',
        ];

        $mailable = new RegisterConfirmation($userData);

        $mailable->assertSeeInHtml('Hi ' . $userData['name']);

        $mailable->assertSeeInHtml('Verify Account');

        $mailable->assertSeeInHtml('https://example.com/confirm/registration/IbXiMcIV9SNDRNn9iPfyss5KK4xko262cFUoQRmGprc2mi7u4sY2pzRN6NmrMuJM');
    }
}
