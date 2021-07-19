<?php

namespace App\Exceptions;

use Illuminate\Http\Request;
use App\Helpers\HttpStatus as Status;

class ValidationException extends BaseException
{
    /**
     * Render the exception into a JSON response.
     *
     * @uses   \App\Providers\ResponseServiceProvider
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function render(Request $request)
    {
        return response()->api([
            'status' => Status::BAD_REQUEST,
            'error' => $this->getMessage(),
        ]);
    }
}
