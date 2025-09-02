import Router from 'express'
import {Chat} from '../utils/schemas/schema.mjs'

const router = Router();


router.get('/api/chats/:errandId', async(request, response) => {
    const {errandId} = request.params;
    const authHeader = request.headers['authorization']; 

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return response.status(401).json({
            message: 'Authorization header missing or improperly formatted',
        });
    }
    
    const token = authHeader.split(' ')[1];
    try {
        if(!token) return response.status(401).json({message:'No token Provided'});
        if(!errandId) return response.status(401).json({message:'Errand ID not found'});

        const messages = await Chat.find({room: errandId});

        response.json({
            message: 'Chats retrieved successfully',
            chats: messages,
        })
    } catch (error) {
        console.log(error)
        response.status(400).json({
            message: 'Error retrieving chats',
            error: error.message
        })
    }
})

router.post('/api/chats/:errandId', async(request, response) => {
    const {errandId} = request.params;
    const {message, senderID} = request.body;
    const authHeader = request.headers['authorization']; 

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return response.status(401).json({
            message: 'Authorization header missing or improperly formatted',
        });
    }
    
    const token = authHeader.split(' ')[1];
    try {
        if(!token) return response.status(401).json({message:'No token Provided'});
        if(!errandId) return response.status(401).json({message:'Errand ID not found'});

        if(!message || !senderID) return response.status(401).json({message:'Message or Sender ID missing'})

        const newMessage = new Chat({
            room: errandId,
            senderID: senderID,
            message: message,
            errandId:errandId
        })

        const savedMessage = await newMessage.save();
        response.json({message: 'Message saved successfully'})

    } catch (error) {
        console.log(error)
        response.status(400).json({
            message: 'Error saving message',
            error: error.message
        })
    }    
})

export default router;