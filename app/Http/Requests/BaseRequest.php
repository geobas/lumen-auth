<?php

namespace App\Http\Requests;

use Log;
use Urameshibr\Requests\FormRequest;
use App\Exceptions\ValidationException;
use Illuminate\Contracts\Validation\Validator;

class BaseRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     *
     * @return bool
     */
    public function authorize(): bool
    {
        return true;
    }

    protected function failedValidation(Validator $validator): void
    {
        Log::error("'" . app()->request->route()[1]['uses'] . ' : ' . implode(', ', $validator->errors()->all()) . "'");

        throw new ValidationException(implode(', ', $validator->errors()->all()));
    }
}
