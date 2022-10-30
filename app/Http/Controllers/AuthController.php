<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Auth\Events\Registered;
use Illuminate\Auth\Events\Verified;
use Validator;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\Rules;
use Illuminate\Support\Str;


class AuthController extends Controller
{
    //

    public function __construct(){
        $this->middleware('auth:api', ['except'=>['register', 'login','verify', 'sendPasswordRestLink', 'resetPassword'] ]);
    }
    

    public function register(Request $request){
        $validator = Validator::make($request->all(), [
            'name' => 'required|string',
            'email' => 'required|string|email|unique:users',
            'password' => 'required|string|confirmed|min:6',
        ],
        [
            'name.required' => 'Kindly enter first name',
            
            'email.required' => 'Kindly enter email',
            'email.unique' => 'Email already exist',
            'password.required' => 'Kindly enter password',
            'password.min' => 'Password should be at least 6 characters'
        ]
    );
        if($validator->fails()){
            return response()->json(($validator->errors()), 400);
        }

        $user = User::create(array_merge(
            $validator->validated(),
            ['password'=> bcrypt($request->password)]
        ));

        event(new Registered($user)); // send email notification to user

        return response()->json([
            'message' => "User created successfully",
            'user' => $user
        ],201);
        // $request->validate([
        //     'name' => 'required|string',
        //     'email' => 'required|string|email:unique::users',
        //     'password' => 'required|string|confirmed|min:6',
        // ]);

    }


    public function login(Request $request){

        $validator = Validator::make($request->all(), [
            
            'email' => 'required|string|email',
            'password' => 'required|string|min:6',
        ]);
        if($validator->fails()){
            return response()->json($validator->errors()->toJson(), 422);
        }
        //$token = auth()->setTTL(7200)->attempt($credentials);
        if(!$token = auth()->attempt($validator->validated())){
            return response()->json(['error' => 'Unathorized'],401);
        }
        return $this->createToken($token);
    }



    public function index(Request $request){
        return response()->json(['message'=> 'Welcome to protected route'],200);
    }

    public function createToken($token){
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL()*60,
            'user' => auth()->user() 
        ]);

    }


    public function verify($id, $hash){

        $user = User::find($id);

        if (!$user) {
           return response()->json(['error' => 'No user found'],401);
        }

        if (!hash_equals($hash, sha1($user->getEmailForVerification()))) {

            return response()->json(['error' => 'invalid or expired link'],401);
        }


        if (!$user->hasVerifiedEmail()) {

            $user->markEmailAsVerified();

            event(new Verified($user));
           return response()->json(['message' => 'Email verified'],200);
        }
    
        return response()->json(['message' => 'Email already verified'],200);

    }


    public function resendVerificationLink(Request $request) {

        $request->user()->sendEmailVerificationNotification();
     
        return response()->json(['message' => 'New verification link sent'],200);
    
    }


    public function sendPasswordRestLink(Request $request){

        $request->validate([
            'email' => ['required', 'email'],
        ]);

        $user = User::where('email',$request->email)->first();

        if (!$user) {
            return response()->json(['error' => 'No user found'],401);
         }

        // We will send the password reset link to this user. Once we have attempted
        // to send the link, we will examine the response then see the message we
        // need to show to the user. Finally, we'll send out a proper response.
        
        $status = Password::sendResetLink($request->only('email'));

         if($status == Password::RESET_LINK_SENT){

            return response()->json(['message' => 'Reset link sent successfully'],200);
         }
       
         return response()->json(['error' => 'Internal server error'],500);
    }


    public function resetPassword(Request $request)
    {

        $request->validate([
            'token' => ['required'],
            'email' => ['required', 'email'],
            'password' => ['required', 'confirmed', Rules\Password::defaults()],
        ]);

        $user = User::where('email',$request->email)->first();

        if (!$user) {
            return response()->json(['error' => 'No user found'],401);
         }

        // Here we will attempt to reset the user's password. If it is successful we
        // will update the password on an actual user model and persist it to the
        // database. Otherwise we will parse the error and return the response.
        $status = Password::reset(
            $request->only('email', 'password', 'password_confirmation', 'token'),
            function ($user) use ($request) {
                $user->forceFill([
                    'password' => Hash::make($request->password),
                    'remember_token' => Str::random(60),
                ])->save();

                event(new PasswordReset($user));
            }
        );


        if($status == Password::PASSWORD_RESET){
            return response()->json(['message' => 'password reset successfully'],200);
        }

        

        return response()->json(['error' => 'Invalid or expired token'],422);
    }
}
