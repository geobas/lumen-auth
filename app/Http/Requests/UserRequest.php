<?php

namespace App\Http\Requests;

use Illuminate\Support\Str;

class UserRequest extends BaseRequest
{
    /**
     * Get the validation rules that apply to the request.
     *
     * @return array
     */
    public function rules(): array
    {
        switch (app()->request->path()) {
            case 'auth/register':
                $rules = [
                    'username' => 'required|email|unique:users',
                    'password' => 'required|min:5|confirmed',
                    'name' => 'required|string',
                    'email_verified' => 'nullable|boolean',
                    'email_verified_at' => 'nullable|date',
                ];

                break;

            case 'auth/login':
                $rules = [
                    'username' => 'required',
                    'password' => 'required',
                ];

                break;

            case 'auth/change/password':
                $rules = [
                    'password' => 'required|min:5|confirmed',
                    'token' => 'required',
                ];

                break;

            case app()->request->method == 'POST' && Str::contains(app()->request->path(), ['admin/users']):
                $rules = [
                    'username' => 'required|email|unique:users,username,' . app()->request->id,
                    'password' => 'required|min:5|confirmed',
                    'name' => 'required|string',
                ];

                break;

            case app()->request->method == 'PUT' && Str::contains(app()->request->path(), ['admin/users']):
                $rules = [
                    'username' => 'required|email|unique:users,username,' . app()->request->id,
                    'password' => 'sometimes|filled|min:5|confirmed',
                    'name' => 'required|string',
                ];

                break;
        }

        return $rules;
    }

    /**
     * Custom message for validation.
     *
     * @return array
     */
    public function messages(): array
    {
        return [
            'username.required' => ':attribute is required',
            'username.email' => ':attribute is not valid',
            'username.unique' => ':attribute must be unique',
            'password.required' => ':attribute is required',
            'password.min' => ':attribute is too small',
            'password.confirmed' => ':attribute confirmation does not match',
            'password.filled' => ':attribute should not be empty',
            'name.required' => ':attribute is required',
            'email_verified.boolean' => ':attribute value is not valid',
            'email_verified_at.date' => ':attribute is not a valid date',
            'token.required' => ':attribute is required',
        ];
    }
}
