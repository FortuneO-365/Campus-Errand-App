import {Router} from 'express';
import {Review} from '../utils/schemas/schema.mjs'
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';

dotenv.config();
const router = Router();

const { Secret } = process.env;

router.post('/api/reviews/:runnerId', async (request, response) => {
    const {rating}   = request.body;
    const {runnerId}  =  request.params;
    const authHeader = request.headers['authorization']; 

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return response.status(401).json({
            message: 'Authorization header missing or improperly formatted',
        });
    }
    
    const token = authHeader.split(' ')[1];
    try {
        if(!token) return response.status(401).json({message:'No token Provided'});
        if(!runnerId) return response.status(401).json({message:'Runner ID not found'});
        if(!rating) return response.status(401).json({message:'Rating not provided'});

        jwt.verify(token, Secret, async (error, decoded) => {
            if (error) return response.status(401).json({message:'Invalid Token'});

            if (!decoded.userId) return response.status(401).json({message:'Unable to get userId'});

            const userId = decoded.userId;

            const rating = new Review({
                userID: userId,
                runnerID: runnerId,
                rating: rating,
            }) 

            const savedRating = await rating.save();

            response.json({
                message: 'Rating posted successfully',
                review: savedRating
            })
        })
    } catch (error) {
        console.log(error);
        response.status(400).json({
            message: 'Error posting Review',
            error: error.message,
        })
    }

})


router.get('/api/reviews/:runnerId', async (request, response) => {
    const {runnerId}  =  request.params;
    const authHeader = request.headers['authorization']; 

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return response.status(401).json({
            message: 'Authorization header missing or improperly formatted',
        });
    }
    
    const token = authHeader.split(' ')[1];

    try {
        if(!token) return response.status(401).json({message:'No token Provided'});
        if(!runnerId) return response.status(401).json({message:'Errand ID not found'});

        const reviews = await Review.find({runnerID: runnerId });

        response.json({
            messsage: 'Ratings retrieved successfully',
            reviews: reviews,
        })

    } catch (error) {
        console.log(error);
        response.status(400).json({
            message: 'Error retieving Reviews',
            error: error.message,
        })
    }

})


export default router;