<?php

namespace App\Http\Controllers\Auth;

use App\Http\Requests\Auth\AuthLogin;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Http\Controllers\Controller;
use App\Http\Resources\Auth\LeaderResource;
use Symfony\Component\HttpFoundation\Response;

class LoginController extends Controller
{
    /**
     * Get a JWT token via given credentials.
     *
     * @param  \Illuminate\Http\Request  $request
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(AuthLogin $request)
    {
        $credentials = $request->only('email', 'password');

        if ($token = auth()->attempt($credentials)) {
            return $this->respondWithToken($token);
        }

        return response()
            ->json(['error' => 'Incorrect email or password !'], Response::HTTP_UNAUTHORIZED)
            ->header('Content-Type', 'application/json');
    }

    /**
     * Get the authenticated User.
     *
     * @return LeaderResource|response
     */
    public function me()
    {
        if ( !$me = $this->guard()->user() ) {
            return response()
                ->json(['error' => 'Sorry! Your token has expired!'], Response::HTTP_UNAUTHORIZED)
                ->header('Content-Type', 'application/json');
        }

        return new LeaderResource(Auth::user());
    }

    /**
     * Log the user out (Invalidate the token)
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        $this->guard()->logout();

        return response()
            ->json(['message' => 'User successfully logged out!'])
            ->header('Content-Type', 'application/json');
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
/*    public function refresh()
    {
        return $this->respondWithToken($this->guard()->refresh());
    }*/

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => $this->guard()->factory()->getTTL() * 60
        ]);
    }

    /**
     * Get the guard to be used during authentication.
     *
     * @return \Illuminate\Contracts\Auth\Guard
     */
    public function guard()
    {
        return Auth::guard();
    }
}
