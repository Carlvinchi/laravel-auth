<?php

use App\Http\Controllers\AuthController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;


/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});

Route::group(['middleware'=>['api'], 'prefix'=>'auth'], function($router){
    Route::post('/register', [AuthController::class, 'register']);

    Route::post('/login', [AuthController::class, 'login']);

    Route::get('/welcome', [AuthController::class, 'index'])->middleware('verified');

    Route::post('/email/verification-notification', [AuthController::class, 'resendVerificationLink'])->middleware(['throttle:6,1'])->name('verification.send');

    Route::get('/api/auth/verify-email/{id}/{hash}', [AuthController::class, 'verify'])->middleware(['signed'])->name('verification.verify');

    Route::post('/reset-link', [AuthController::class, 'sendPasswordRestLink']);

    Route::post('/reset-password', [AuthController::class, 'resetPassword']);
});


 
