import {Router} from 'express';
import {Notification} from '../utils/schemas/schema.mjs'
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';

dotenv.config();
const router = Router();

const { Secret } = process.env;

router.get('/api/notifications', async (request, response) => {
    const authHeader = request.headers['authorization']; 

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return response.status(401).json({
            message: 'Authorization header missing or improperly formatted',
        });
    }
    
    const token = authHeader.split(' ')[1];
    try {
        if (!token) return response.status(401).json({message:'No token Provided'});

        jwt.verify(token, Secret, async (error, decoded) => {
            if (error) return response.status(401).json({message:'Invalid Token'});

            const userId  = decoded.userId;
            const notifications = await Notification.find({userID: userId});

            response.json({
                message: 'Notifications gotten successfully',
                notifications: notifications
            })

        })
    } catch (error) {
        console.log(error);
        response.status(400).json({
            message: 'Error retrieving Notifications',
            error: error.message,
        })
    }
})

router.post('/api/notifications/read', async (request, response) => {
    const {id} = request.body;
    const authHeader = request.headers['authorization']; 

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return response.status(401).json({
            message: 'Authorization header missing or improperly formatted',
        });
    }
    
    const token = authHeader.split(' ')[1];
    try {
        if(!token) return response.status(401).json({message:'No token provided'});
        if(!id) return response.status(401).json({message:'Notification ID not found'});

        const notification = await Notification.findById(id);

        notification.status = 'read';

        const readNotifcation = await notification.save();

        response.json({
            message: 'Notification read successfully',
            notification: readNotifcation,
        })
    } catch (error) {
        console.log(error);
        response.status(400).json({
            message: 'Error marking notification as read',
            error: error.message,
        })
    }
})

export default router