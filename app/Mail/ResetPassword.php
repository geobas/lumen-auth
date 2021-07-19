<?php

namespace App\Mail;

use Illuminate\Bus\Queueable;
use Illuminate\Mail\Mailable;
use Illuminate\Queue\SerializesModels;

class ResetPassword extends Mailable
{
    use Queueable, SerializesModels;

    /**
     * The user details.
     *
     * @var object
     */
    public $userData;

    /**
     * Create a new message instance.
     *
     * @param array  $userData
     */
    public function __construct(array $userData)
    {
        $this->userData = (object) $userData;
    }

    /**
     * Build the message.
     *
     * @return self
     */
    public function build(): self
    {
        return $this->view('emails.reset-password')
                    ->subject('Reset your password')
                    ->with('url', config('app.reset_password_url'));
    }
}
