<?php

namespace App\Customs\Services;

use Illuminate\Support\Str;
use App\Models\EmailVerificationToken;
use App\Models\User;
use App\Notifications\EmailVerificationNotification;
use Illuminate\Support\Facades\Notification;

class EmailVerificationService {

    /**
     * Send verification link to a user
     */

     public function sendVerificationLink(object $user): void
     {
        Notification::send($user, new EmailVerificationNotification($this->generateVerificationLink($user->email)));
     }

     /**
      * Resend link with token
      */
      public function resendLink($email) {
            $user =  User::where('email', $email)->first();
            if($user) {
                $this->sendVerificationLink($user);
                return response()->json([
                    'status' => 'success',
                    'message' => 'Verification link sent sucessfully'
                ]);
            } else {
                return response()->json([
                    'status' => 'failed',
                    'message' => 'user not found'
                ]);
            }
      }

     /**
      * Check if user has already verified
      */

      public function checkIfEmailIsVerified($user) {
        if($user->email_verified_at) {
            response()->json([
                'status' => 'failed',
                'message' => 'Email has already been verified'
            ])->send();
            exit;

        }
      }

      /**
       * Verify user email
       */
      public function verifyEmail(string $email, string $token) {

        $user = User::where('email', $email)->first();
        if(!$user) {
            response()->json([
                'status' => 'failed',
                'message' => 'user not found'
            ])->send();
            exit;
        }
        $this->checkIfEmailIsVerified($user);
        $verifiedToken = $this->verifyToken($email, $token);
        if($user->markEmailAsVerified()) {
            $verifiedToken->delete();
            return response()->json([
                'status' => 'success',
                'message' => 'Email has been verified successfully'
            ]);
        }else {
            return response()->json([
                'status' => 'failed',
                'message' => 'Email verification failed, please try again.'
            ]);
        }
      }

     /**
      * Verify token
      */

      public function verifyToken(string $email, string $token) {
        $token = EmailVerificationToken::where('email', $email)->where('token',$token)->first();
        if($token) {
            if($token->expired_at >= now()) {
                return $token;
             }else {
                $token->delete();
                response()->json([
                    'status' => 'failed',
                    'message' => 'Token expired'
                ])->send();
                exit;
             }
        }else {
            response()->json([
                'status' => 'failed',
                'message' => 'Invalid token'
            ])->send();
            exit();
        }
      }
    /**
     * Generate verification link
     */

     public function generateVerificationLink(string $email): string
     {
        $checkIfTokenExists = EmailVerificationToken::where('email', $email)->first();

        if($checkIfTokenExists) $checkIfTokenExists->delete();
        $token = Str::uuid();
        $url = config('app.url')."?token=".$token."&email=".$email;
        $saveToken =  EmailVerificationToken::create([
            'email' => $email,
            'token' => $token,
            'expired_at' => now()->addMinutes(60),
        ]);

        if($saveToken) {
            return $url;
        }
     }
}
