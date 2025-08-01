import {Router} from 'express';
import {User} from '../utils/schemas/schema.mjs'
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();
const router = Router();


var token;
const { Secret } = process.env;

router.post('/api/auth/register', async (request, response) => {
    const { 
        name, 
        email, 
        password, 
        role
    } = request.body;

    const user = new User({
        name,
        email,
        password,
        role
    });

    try{
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return response.status(409).json({
                message: 'User already registered with this email',
            });
        }

        const savedUser = await user.save();
        response.status(200).json({
            message: 'User registered successfully',
            user: savedUser
        });
    }catch(error){
        console.log(error);
        response.status(500).json({
            message: 'Error registering user',
            error: error.message
        });
    }
});

router.post('/api/auth/login', async (request, response) => {
    const {email, password} = request.body;
    try{
        if(!email) throw new Error('User Email not found');
        if(!password) throw new Error('User Password not found');
        const salt = await bcrypt.genSalt(10);
        const encryptedPassword = await bcrypt.hash(password, salt)
        console.log(encryptedPassword);
        const user = await User.findOne({email: email});
        if(user){

            const isMatch = await bcrypt.compare(password, user.password);
            if(!isMatch){
                throw new Error('Invalid Credentials');
            }else{
                token = jwt.sign({
                    userId: user._id,
                    userName: user.name,
                    userEmail: user.email,
                    userRole: user.role 
                },Secret,{expiresIn: '2h'})
    
                response.json({
                    message: 'Login Successful',
                    user: {
                        Id: user._id,
                        Name: user.name,
                        Email: user.email,
                        Role: user.role
                    },
                    token: token,
                })
            }

        }else{
            throw new Error('User not Found');
        }
    }catch(error){
        console.log(error);
        response.status(401).json({
            message: 'Login Error',
            error: error.message
        })
    }
})

router.get('/api/auth/me', async (request, response) => {
    const authHeader = request.headers['authorization']; 
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return response.status(401).json({
            message: 'Authorization header missing or improperly formatted',
        });
    }

    const token = authHeader.split(' ')[1]; 
    try {
        if (!token) throw new Error('No token found');
        jwt.verify(token, Secret, async (error, decoded) => {
            if (error) {
                throw new Error('Invalid Token');
            } else {
                response.json({
                    user: decoded,
                });
            }
        });
    } catch (error) {
        console.log(error);
        response.status(401).json({
            message: 'Unable to get user details',
            error: error.message,
        });
    }
});

router.put('/api/auth/change-password', async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    const authHeader = req.headers['authorization'];

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Authorization header missing or improperly formatted' });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = await verifyToken(token, Secret); // Verify JWT token
        const user = await User.findById(decoded.userId);

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const isMatch = await bcrypt.compare(oldPassword, user.password); // Compare old password
        if (!isMatch) {
            return res.status(400).json({ message: 'Old password is incorrect' });
        }

        user.password = await bcrypt.hash(newPassword, 10); // Hash new password
        await user.save();

        res.status(200).json({ message: 'Password updated successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error', error: error.message });
    }
});

router.post('/api/auth/forgot-password', async (req, res) => {
    const { email } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Generate a reset token
        const resetToken = crypto.randomBytes(32).toString('hex');
        const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');

        // Save the hashed token and expiration time in the database
        user.resetPasswordToken = hashedToken;
        user.resetPasswordExpires = Date.now() + 3600000; // Token valid for 1 hour
        await user.save();

        // Send the reset token via email (mocked here)
        console.log(`Password reset token for ${email}: ${resetToken}`);

        res.status(200).json({ message: 'Password reset token sent to email' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error', error: error.message });
    }
});

router.post('/api/auth/reset-password', async (req, res) => {
    const { resetToken, newPassword } = req.body;

    try {
        // Hash the provided reset token to match the stored hashed token
        const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');

        const user = await User.findOne({
            resetPasswordToken: hashedToken,
            resetPasswordExpires: { $gt: Date.now() }, // Ensure token is not expired
        });

        if (!user) {
            return res.status(400).json({ message: 'Invalid or expired reset token' });
        }

        // Update the user's password
        user.password = await bcrypt.hash(newPassword, 10);
        user.resetPasswordToken = undefined; // Clear the reset token
        user.resetPasswordExpires = undefined; // Clear the expiration time
        await user.save();

        res.status(200).json({ message: 'Password reset successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error', error: error.message });
    }
});

export default router