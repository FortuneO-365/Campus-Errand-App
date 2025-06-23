import {Router} from 'express';
import {User} from '../utils/schemas/schema.mjs'
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';

dotenv.config();
const router = Router();

const { Secret } = process.env;

router.get('/api/users/:id', async (request,response) =>{
    const {id} = request.params;
    const authHeader = request.headers['authorization']; 
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return response.status(401).json({
            message: 'Authorization header missing or improperly formatted',
        });
    }
    
    const token = authHeader.split(' ')[1]; 
    try{
        if(!token) throw new Error('No token found');
        const user = await User.findById(id);
        if(!user){
            throw new Error('User not found');
        }else{
            response.json({
                message: 'User found',
                user: user
            })
            
        }
    }catch(error){
        console.log(error);
        response.status(404).json({
            message: 'Error getting user',
            error: error.message
        })
    }
})


router.patch('/api/users/:id', async (request, response) => {
    const {
        body,
        params: { id }
    } = request;

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
            if (error) throw new Error('Invalid Token');
            
            if (decoded.userRole !== 'admin' || decoded.userId !== id) {
                return response.status(403).json({
                    message: 'Forbidden: You do not have permission to update this user',
                });
            }

            const user = await User.findById(id);
            if (!user) {
                throw new Error('User not found');
            } else {
                Object.assign(user, body); // Update user fields with request body
                const updatedUser = await user.save(); // Save the updated user
                response.json({
                    message: 'User updated',
                    user: updatedUser
                });
            }
        });
    } catch (error) {
        console.log(error);
        response.status(400).json({
            message: 'Error updating user',
            error: error.message
        });
    }
});

router.get('/api/runners', async (request, response) => {
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
            if (error) throw new Error('Invalid Token');

            if (decoded.userRole !== 'admin') {
                return response.status(403).json({
                    message: 'Forbidden: You do not have permission to access this endpoint',
                });
            }

            const runners = await User.find({ role: 'runner' }); 
            response.json({
                message: 'Runners retrieved successfully',
                runners: runners,
            });
        });
    } catch (error) {
        console.log(error);
        response.status(500).json({
            message: 'Error retrieving runners',
            error: error.message,
        });
    }
});

export default router;