<?php

namespace App\Models;

use Carbon\Carbon;
use Illuminate\Support\Str;
use Illuminate\Http\Request;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Builder;

class PasswordReset extends Model
{
    /**
     * Indicates if the model should be timestamped.
     *
     * @var bool
     */
    public $timestamps = false;

    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = [
        'username',
        'token',
        'created_at',
    ];

    /**
     * Return the generated reset token for a specific username.
     *
     * @param  \Illuminate\Database\Eloquent\Builder  $query
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Database\Eloquent\Builder
     */
    public function scopeGetToken(Builder $query, Request $request): Builder
    {
        return $query->select('token')
    				 ->where('username', $request->username);
    }

    /**
     * Create a new reset token.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return self
     */
    public function createToken(Request $request): self
    {
        return $this->create([
            'username' => $request->username,
            'token' => Str::random(64),
            'created_at' => Carbon::now(),
        ]);
    }

    /**
     * Return the username for a specific reset token.
     *
     * @param  \Illuminate\Database\Eloquent\Builder  $query
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Database\Eloquent\Builder
     */
    public function scopeGetUsername(Builder $query, Request $request): Builder
    {
        return $query->select('username')
    				 ->where('token', $request->token);
    }

    /**
     * Remove a reset token.
     *
     * @param  \Illuminate\Database\Eloquent\Builder  $query
     * @param  \App\Models\User  $user
     * @return int
     */
    public function scopeDeleteToken(Builder $query, User $user): int
    {
        return $query->where('username', $user->username)
    				 ->delete();
    }
}
