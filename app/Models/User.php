<?php

namespace App\Models;

use Illuminate\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Access\Authorizable as AuthorizableContract;
use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Laravel\Lumen\Auth\Authorizable;
use Illuminate\Support\Str;
use Illuminate\Database\Eloquent\Builder;
use Carbon\Carbon;
use App\Http\Requests\UserRequest;
use Tymon\JWTAuth\Contracts\JWTSubject;

class User extends Model implements AuthenticatableContract, AuthorizableContract, JWTSubject
{
    use Authenticatable, Authorizable, HasFactory;

    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = [
        'username',
        'password',
        'name',
        'email_verification_token',
        'email_verified',
        'email_verified_at',
    ];

    /**
     * The attributes excluded from the model's JSON form.
     *
     * @var array
     */
    protected $hidden = [
        'password',
        'email_verification_token',
        'email_verified',
        'email_verified_at',
    ];

    /**
     * Set the user's password.
     *
     * @param  string  $value
     * @return void
     */
    public function setPasswordAttribute(string $value): void
    {
        $this->attributes['password'] = app('hash')->make($value);
    }

    /**
     * Get the identifier that will be stored in the subject claim of the JWT.
     *
     * @return mixed
     */
    public function getJWTIdentifier()
    {
        return $this->getKey();
    }

    /**
     * Return a key value array, containing any custom claims to be added to the JWT.
     *
     * @return array
     */
    public function getJWTCustomClaims(): array
    {
        return [];
    }

    /**
     * Create a new User.
     *
     * @param  \App\Http\Requests\UserRequest  $request
     * @return self
     */
    public function new(UserRequest $request): self
    {
        return $this->create([
            'username' => $request->username,
            'password' => $request->password,
            'name' => $request->name,
            'email_verification_token' => Str::random(64),
        ]);
    }

    /**
     * Return a specific User.
     *
     * @param  \Illuminate\Database\Eloquent\Builder  $query
     * @param  string  $option
     * @return \Illuminate\Database\Eloquent\Builder
     */
    public function scopeFetch(Builder $query, string $option): Builder
    {
        return $query->select(['id', 'username', 'name', 'email_verified', 'email_verified_at', 'created_at'])
                     ->where('username', $option)
                     ->orWhere('email_verification_token', $option);
    }

    /**
     * Confirm a User's registration.
     *
     * @return void
     */
    public function confirmRegistration(): void
    {
        $this->update([
            'email_verification_token' => '',
            'email_verified' => 1,
            'email_verified_at' => Carbon::now()->format('Y-m-d H:i:s'),
        ]);
    }      
}
