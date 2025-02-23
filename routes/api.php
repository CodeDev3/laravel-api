<?php

use App\Http\Controllers\Api\ApiController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Middleware\JwtMiddleware;

Route::post('register', [ApiController::class, 'register']);
Route::post('login', [ApiController::class, 'login']);
Route::post('forget-password', [ApiController::class, 'forgetPassword']);
Route::post('verifyOTP', [ApiController::class, 'verifyOTP']);
Route::post('resetPassword', [ApiController::class, 'resetPassword']);

Route::middleware([JwtMiddleware::class])->group(function () {
    Route::get('userProfile', [ApiController::class, 'getUser']);
    Route::post('updateProfile', [ApiController::class, 'updateProfile']);
    Route::post('logout', [ApiController::class, 'logout']);
});
