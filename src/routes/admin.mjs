import {Router} from 'express';
import {Errand, User} from '../utils/schemas/schema.mjs'
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';

dotenv.config();
const router = Router();

const { Secret } = process.env;

router.get('/api/admin/requests', async (request, response) => {
    
    const authHeader = request.headers['authorization']; 
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return response.status(401).json({
            message: 'Authorization header missing or improperly formatted',
        });
    }
    
    const token = authHeader.split(' ')[1];

    try {
        if (!token) throw new Error('No token Provided')

        jwt.verify(token, Secret, async (error, decoded) => {
            if (error) throw new Error('Invalid Token')

            if (decoded.userRole !== 'admin') {
                return response.status(403).json({
                    message: 'Forbidden: You do not have permission to access this endpoint'
                })
            }

            const errands = await Errand.find();

            response.json({
                message: 'Errands retrieved successfully',
                errands: errands
            })
        })    
    } catch (error) {
        console.log(error);
        response.status(400).json({
            message: 'Error retrieving errands',
            error: error.message
        })
    }
})

router.get('/api/admin/users', async (request, response) => {
        
    const authHeader = request.headers['authorization']; 
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return response.status(401).json({
            message: 'Authorization header missing or improperly formatted',
        });
    }
    
    const token = authHeader.split(' ')[1];

    try {
        if (!token) throw new Error('No token Provided')

        jwt.verify(token, Secret, async (error, decoded) => {
            if (error) throw new Error('Invalid Token')

            if (decoded.userRole !== 'admin') {
                return response.status(403).json({
                    message: 'Forbidden: You do not have permission to access this endpoint'
                })
            }

            const users = await User.find({role : 'user'});

            response.json({
                message: 'Errands retrieved successfully',
                users: users
            })
        })    
    } catch (error) {
        console.log(error);
        response.json({
            message: 'Error retrieving users',
            error: error.message
        })
    }
})

router.delete('/api/admin/users/:id', async (request, response) => {
    const {id} = request.params;

    const authHeader = request.headers['authorization']; 
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return response.status(401).json({
            message: 'Authorization header missing or improperly formatted',
        });
    }
    
    const token = authHeader.split(' ')[1];

    try {

        if (!token) throw new Error('No token provided');
        
        jwt.verify(token, Secret, async (error, decoded) => {
            if (error) throw new Error('Invalid Token');

            if (decoded.userRole !== 'admin') {
                return response.status(400).json({
                    message: 'Forbidden: You do not have permission to access this endpoint'
                })
            }

            const user = await User.findById(id);
            if (!user) throw new Error('User not found');

            await user.deleteOne();

            response.status(200).json({
                message: 'User deleted successfully',
            });
        })
    } catch (error) {
        console.log(error);
        response.json({
            message: 'Error deleting user',
            error: error.message
        })
    }
})

export default router;