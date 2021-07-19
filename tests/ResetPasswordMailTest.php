<?php

use App\Mail\ResetPassword;

class ResetPasswordMailTest extends TestCase
{
    /**
     * @test
     */
    public function reset_password_mailable_content()
    {
        $userData = [
            'username' => 'dummy@user.com',
            'name' => 'John Doe',
            'token' => 'fQq2eNiy2dYtjFUPVhFjaP6R5dJOLPtAsn4p2xW3HzPvdtSF5nj20gmGViYHTu7E',
        ];

        $mailable = new ResetPassword($userData);

        $mailable->assertSeeInHtml('Hi ' . $userData['name']);

        $mailable->assertSeeInHtml('account: ' . $userData['username']);

        $mailable->assertSeeInHtml('Set new password');

        $mailable->assertSeeInHtml('https://example.com/reset/password/fQq2eNiy2dYtjFUPVhFjaP6R5dJOLPtAsn4p2xW3HzPvdtSF5nj20gmGViYHTu7E');
    }
}
