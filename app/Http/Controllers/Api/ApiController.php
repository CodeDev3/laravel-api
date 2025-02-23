<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Support\Facades\DB;

// use Illuminate\Container\Attributes\DB;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;
use Illuminate\Support\Facades\Storage;

class ApiController extends Controller
{
    // Register API - POST (name, email, password)
    public function register(Request $request)
    {
        $request->validate([
            "name" => "required|string",
            "username" => "required|string",
            "email" => "required|string|email|unique:users",
            "password" => "required|confirmed",
            "dob" => "required|date",
            "mobile" => "required|string|size:10",
        ]);

        try {
            $user = User::create([
                'name' => $request->get('name'),
                'username' => $request->get('username'),
                'email' => $request->get('email'),
                'password' => Hash::make($request->get('password')),
                'dob' => $request->get('dob'),
                'mobile' => $request->get('mobile'),
            ]);
            $token = JWTAuth::fromUser($user);
            return $this->successResponse('success', "User Registered Successfully", []);
        } catch (\Exception $e) {
            return $this->errorResponse(false, "Registration failed. Please try again.");
        }
    }

    public function updateProfile(Request $request)
    {
        // Get the authenticated user
        if (!$user = JWTAuth::parseToken()->authenticate()) {
            return response()->json(['error' => 'User not found'], 404);
        }

        // Validate the request
        $request->validate([
            'firstname' => 'sometimes|string',
            'lastname' => 'sometimes|string',
            'username' => 'sometimes|string|unique:users,username,' . $user->id,
            'email' => 'sometimes|email|unique:users,email,' . $user->id,
            'password' => 'sometimes|min:6',
            'dob' => 'sometimes|date',
            'mobile' => 'sometimes|required|string|size:10',
            'profileImage' => 'sometimes|string',
        ]);

        try {
            if ($request->has('firstname') || $request->has('lastname')) $user->name = $request->get('firstname') . ' ' . $request->get('lastname');
            if ($request->has('username')) $user->username = $request->get('username');
            if ($request->has('email')) $user->email = $request->get('email');
            if ($request->has('dob')) $user->dob = $request->get('dob');
            if ($request->has('mobile')) $user->mobile = $request->get('mobile');
            if ($request->has('password')) $user->password = Hash::make($request->get('password'));

            if ($request->has('profileImage') && (!filter_var($request->get('profileImage'), FILTER_VALIDATE_URL))) {

                $imageData = $request->get('profileImage');
                $filePath = $this->uploadImage($imageData);
                if (!$filePath) {
                    return $this->errorResponse('error', "Failed to upload profile image. Please try again.");
                } else {

                    $user->profileImage = 'http://localhost:8000/storage/' . $filePath;
                }
            }

            $user->save();

            return $this->successResponse('success', "Profile updated successfully", $user);
        } catch (\Exception $e) {
            return $this->errorResponse('error', "Profile update failed. Please try again.");
        }
    }

    //uploadImage function to handle profile image upload
    public function uploadImage($imageData)
    {
        // Remove the prefix (data:image/jpeg;base64,) if present
        if (preg_match('/^data:image\/(\w+);base64,/', $imageData, $type)) {
            $imageData = substr($imageData, strpos($imageData, ',') + 1);
            $type = strtolower($type[1]); // Extract image type (jpeg, png, etc.)
            $imageData = base64_decode($imageData);

            if ($imageData === false) {
                return response()->json(['error' => 'Base64 decode failed'], 400);
            }

            $fileName = uniqid('image_') . '.' . $type;
            $filePath = 'images/' . $fileName;

            Storage::disk('public')->put($filePath, $imageData);
            return $filePath;
        }
    }

    //successResponse and errorResponse functions to handle API responses
    public function successResponse($status, $message, $data = [])
    {
        return response()->json([
            "status" => 'success',
            "message" => $message,
            "data" => $data
        ], 200);
    }
    public function errorResponse($error_type, $message)
    {
        return response()->json([
            "status" => 'failed',
            "error_type" => $error_type,
            "message" => $message,
        ], 400);
    }


    // Login API - POST (email, password)
    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);
        $credentials = $request->only('email', 'password');

        $token = JWTAuth::attempt($credentials);
        if (!$token) {
            return $this->errorResponse('error', 'Invalid login credentials');
        }

        $user = JWTAuth::user();
        $user['token'] = $token;
        return $this->successResponse('success', 'User logged in successfully', $user);
    }


    // Get authenticated user
    public function getUser()
    {
        try {
            if (!$user = JWTAuth::parseToken()->authenticate()) {
                return response()->json(['error' => 'User not found'], 404);
            }
        } catch (JWTException $e) {
            return $this->errorResponse('error', $e->getMessage());
        }
        // $user['token'] = JWTAuth::fromUser($user);
        return $this->successResponse('success', 'User retrieved successfully', $user);
    }


    // Logout API - GET (JWT Auth Token)
    public function logout()
    {

        JWTAuth::invalidate(JWTAuth::getToken());

        return $this->successResponse('success', "User Logged Out Successfully");
    }

    public function forgetPassword(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
        ]);

        $user = User::where('email', $request->email)->first();

        if (!$user) {
            return $this->errorResponse('error', 'Invalid Email');
        }
        $otp = rand(100000, 999999);
        DB::table('password_reset_tokens')->updateOrInsert(
            ['email' => $request->email], // Condition to match
            [
                'token' => $otp,           // Fields to update/insert
                'created_at' => now(),
            ]
        );
        $data = DB::table('password_reset_tokens')
            ->where('email', $request->email)
            ->first();
        return $this->successResponse('success', 'OTP sent successfully', $data);
    }

    public function verifyOTP(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'otp' => 'required|numeric',
        ]);

        $data = DB::table('password_reset_tokens')
            ->where('email', $request->email)
            ->where('token', $request->otp)
            ->first();

        if (!$data) {
            return $this->errorResponse('error', 'Invalid OTP or Email');
        }

        DB::table('password_reset_tokens')
            ->where('email', $request->email)
            ->delete();

        return $this->successResponse('success', 'OTP verified successfully');
    }
    public function resetPassword(Request $request)
    {

        $request->validate([
            'email' => 'required|email',
            'password' => 'required|confirmed|min:8',
        ]);
        $user = User::where('email', $request->email)->first();
        if (!$user) {
            return $this->errorResponse('error', 'Invalid Email');
        }
        $user->password = Hash::make($request->password);
        $user->save();
        return $this->successResponse('success', 'Password reset successfully');
    }
}
