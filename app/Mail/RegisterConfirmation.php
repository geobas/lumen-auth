<?php

namespace App\Mail;

use Illuminate\Bus\Queueable;
use Illuminate\Mail\Mailable;
use Illuminate\Queue\SerializesModels;

class RegisterConfirmation extends Mailable
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
        return $this->view('emails.register')
                    ->subject('Activate your account')
                    ->with('url', config('app.registration_url'));
    }
}
