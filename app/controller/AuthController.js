const sendEmailVerificationOTP = require('../helper/sendEmailVerify')
const { hashPassword, comparePassword } = require('../middleware/auth')
const User = require('../model/user')
const jwt = require('jsonwebtoken')
const EmailVerifyModel = require('../model/otpModel')
const transporter=require('../config/emailConfig')
const bcrypt=require('bcryptjs')



class AuthController {

    async register(req, res) {
        try {
            const { name, email, password } = req.body
            if (!name || !email || !password) {
                return res.status(400).json({
                    status: false,
                    message: "all filed is required"
                })
            }

            const existUser = await User.findOne({ email })
            if (existUser) {
                return res.status(400).json({
                    status: false,
                    message: "user already exist"
                })
            }
            const hashedPassword = hashPassword(password)
            const userdata = new User({
                name,
                email,
                password: hashedPassword
            })
            const user = await userdata.save()
            sendEmailVerificationOTP(req, user)
            return res.status(200).json({
                status: true,
                message: "user register successfully an send otp in your mail id please verify mail",
                data: user
            })

        } catch (error) {
            return res.status(400).json({
                error: error.message
            })
        }

    }


    async verifyAccount(req, res) {
        try {
            const { email, otp } = req.body;
            // Check if all required fields are provided
            if (!email || !otp) {
                return res.status(400).json({ status: false, message: "All fields are required" });
            }
            const existingUser = await User.findOne({ email });

            // Check if email doesn't exists
            if (!existingUser) {
                return res.status(404).json({ status: "failed", message: "Email doesn't exists" });
            }

            // Check if email is already verified
            if (existingUser.is_verified) {
                return res.status(400).json({ status: false, message: "Email is already verified" });
            }
            // Check if there is a matching email verification OTP
            const emailVerification = await EmailVerifyModel.findOne({ userId: existingUser._id, otp });
            if (!emailVerification) {
                if (!existingUser.is_verified) {
                    // console.log(existingUser);
                    await sendEmailVerificationOTP(req, existingUser);
                    return res.status(400).json({ status: false, message: "Invalid OTP, new OTP sent to your email" });
                }
                return res.status(400).json({ status: false, message: "Invalid OTP" });
            }
            // Check if OTP is expired
            const currentTime = new Date(); 
            // 5 * 60 * 1000 calculates the expiration period in milliseconds(15 minutes).
            const expirationTime = new Date(emailVerification.createdAt.getTime() + 5 * 60 * 1000);
            if (currentTime > expirationTime) {
                // OTP expired, send new OTP
                await sendEmailVerificationOTP(req, existingUser);
                return res.status(400).json({ status: "failed", message: "OTP expired, new OTP sent to your email" });
            }
            // OTP is valid and not expired, mark email as verified
            existingUser.is_verified = true;
            await existingUser.save();

            // Delete email verification document
            await EmailVerifyModel.deleteMany({ userId: existingUser._id });
            return res.status(200).json({ status: true, message: "Email verified successfully" });


        } catch (error) {
            console.error(error);
            res.status(500).json({ status: false, message: "Unable to verify email, please try again later" });
        }
    }

    async login(req, res) {
        try {
            const { email, password } = req.body;
            // User.validate(email, password) 
            if (!email || !password) {
                return res.status(400).json({
                    message: 'All fields are required'
                });
            }
            //find user
            const user = await User.findOne({ email });
            console.log('user', user);

            if (!user) {
                return res.status(400).json({
                    message: 'User not found'
                });
            }
            // Check if user verified
            if (!user.is_verified) {
                return res.status(401).json({ status: false, message: "Your account is not verified" });
            }
            const isMatch = comparePassword(password, user.password);
            if (!isMatch) {
                return res.status(400).json({
                    message: 'Invalid credentials'
                });
            }


            // Generate and send the token
            const token = jwt.sign({
                _id: user._id,
                name: user.name,
                email: user.email
            }, process.env.JWT_SECRECT, { expiresIn: "30m" })

            res.status(200).json({
                status: true,
                message: 'Login successful',
                user: {
                    id: user._id,
                    name: user.name,
                    email: user.email
                },
                token,
            });

        } catch (error) {
            return res.status(400).json({
                error: error.message
            })
        }

    }



    async dashboard(req, res) {
        res.status(200).json({
            status: true,
            message: "welcome to user dashboard",
            data: req.user
        })
    }


    async updatePassword(req, res) {
        try {
            const user_id = req.body.user_id;
            const { password } = req.body;
            if (!password) {
                return res.status(400).json({
                    message: 'Password is required'
                });
            }
            const userdata = await User.findOne({ _id: user_id });
            if (userdata) {
                const newPassword = await hashPassword(password);
                const updateuser = await User.findOneAndUpdate({ _id: user_id },
                    {
                        $set: {
                            password: newPassword
                        }
                    });
                res.status(200).json({
                    message: 'Password updated successfully',

                });
            } else {
                res.status(400).json({
                    message: 'password not updated'
                });
            }

        } catch (err) {
            console.log(err);
        }
    }

     //reset password link

     async resetPasswordLink(req,res){
        try{
            const { email } = req.body;
            if (!email) {
              return res.status(400).json({ status:false, message: "Email field is required" });
            }
            const user = await User.findOne({ email });
            if (!user) {
              return res.status(404).json({ status:false, message: "Email doesn't exist" });
            }
            // Generate token for password reset
            const secret = user._id + process.env.JWT_SECRECT;
            const token = jwt.sign({ userID: user._id }, secret, { expiresIn: '20m' });
            // Reset Link and this link generate by frontend developer
            const resetLink = `${process.env.FRONTEND_HOST}/account/reset-password-confirm/${user._id}/${token}`;
            //console.log(resetLink);
            // Send password reset email  
            await transporter.sendMail({
              from: process.env.EMAIL_FROM,
              to: user.email,
              subject: "Password Reset Link",
              html: `<p>Hello ${user.name},</p><p>Please <a href="${resetLink}">Click here</a> to reset your password.</p>`
            });
            // Send success response
            res.status(200).json({ status:true, message: "Password reset email sent. Please check your email." });
      
          }catch(error){
            console.log(error);
            res.status(500).json({ status:false, message: "Unable to send password reset email. Please try again later." });
      
          }

    }


    async resetPassword(req,res){
        try{
            const { password, confirm_password } = req.body;
           const { id, token } = req.params;
           const user = await User.findById(id);
           if (!user) {
             return res.status(404).json({ status:false, message: "User not found" });
           }
           // Validate token check 
           const new_secret = user._id + process.env.JWT_SECRECT;
           jwt.verify(token, new_secret);
     
           if (!password || !confirm_password) {
             return res.status(400).json({ status:false, message: "New Password and Confirm New Password are required" });
           }
     
           if (password !== confirm_password) {
             return res.status(400).json({ status:false, message: "New Password and Confirm New Password don't match" });
           }
            // Generate salt and hash new password
            const salt = await bcrypt.genSalt(10);
            const newHashPassword = await bcrypt.hash(password, salt);
      
            // Update user's password
            await User.findByIdAndUpdate(user._id, { $set: { password: newHashPassword } });
      
            // Send success response
            res.status(200).json({ status: true, message: "Password reset successfully" });
      
         }catch(error){
           return res.status(500).json({ status: false, message: "Unable to reset password. Please try again later." });
         }
    }
}



module.exports = new AuthController()