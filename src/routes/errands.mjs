import { Router } from "express";
import {Errand} from '../utils/schemas/schema.mjs'
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';

dotenv.config();
const router = Router();

const { Secret } = process.env;

router.post('/api/errands', async (request, response) => {
    const {
        title,
        description,
        pickupLocation,
        dropoffLocation,
        price
    } = request.body;

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
            if (error) throw new Error('Invalid Token');

            if (!decoded.userId) throw new Error('Unable to get userId');

            const userId = mongoose.Types.ObjectId(decoded.userId);

            const errand = new Errand({
                userId,
                title, 
                description,
                pickupLocation,
                dropoffLocation,
                price
            });

            const savedErrand = await errand.save();

            response.status(200).json({
                message: 'Errand created successfully',
                errand: savedErrand
            });
        })
    } catch (error) {
        console.log(error);
        response.status(500).json({
            message: 'Error creating errand',
            error: error.message
    })
    }
})

router.get('/api/errands', async (request, response) => {
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
            if (error) throw new Error('Invalid Token');

            if (!decoded.userId) throw new Error('Unable to get userId');

            const errands = await Errand.find({userId: decoded.userId});

            response.json({
                message: 'Errands received successfully',
                errands : errands
            })
            
        })
    } catch (error) {
        console.log(error);
        response.json({
            message: 'Error retrieving errands',
            error: error.message
    })
    }
})

router.get('/api/errands/available', async (request, response) => {
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
            if (error) throw new Error('Invalid Token');

            if (decoded.userRole !== 'runner') {
                return response.status(403).json({
                    message: 'Forbidden: You do not have permission to access this endpoint',
                });
            }

            const errands = await Errand.find({status: 'available'});

            response.json({
                message: 'Errands received successfully',
                errands : errands
            })
            
        })
    } catch (error) {
        console.log(error);
        response.json({
            message: 'Error retrieving errands',
            error: error.message
    })
    }
})

router.get('/api/errands/:id', async (request, response) => {
    const {id} = request.params;

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
            if (error) throw new Error('Invalid Token');

            const errandDetails = await Errand.findById(id);
            if(!errandDetails) throw new Error('Errand not found')

            response.json({
                message: 'Errand fetched successfully',
                errand: errandDetails
            })
        })
    
    } catch (error) {
        console.log(error);
        response.status(400).json({
            message: 'Error fetching errands',
            error: error.message
    })
    }
})

router.patch('/api/errands/:id/accept', async (request, response) => {
    const {id} = request.params;

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
            if (error) throw new Error('Invalid Token');

            if (decoded.userRole !== 'runner'){
                return response.status(403).json({
                    message: 'Forbidden: You do not have permission to access this endpoint'
                })
            }

            const errand = await Errand.findById(id);
            if(!errand) throw new Error('Errand not found')

            errand.status = 'accepted'

            const acceptedErrand = await errand.save();
            response.json({
                message: 'Errand accepted successfully',
                errand: acceptedErrand
            })
        })
    }catch(error){
        console.log(error);
        response.status(400).json({
            message: 'Error accepting errand',
            error: error.message
    })
    }
})

router.patch('/api/errands/:id/complete', async (request, response) => {
    const {id} = request.params;

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
            if (error) throw new Error('Invalid Token');

            if (decoded.userRole !== 'runner'){
                return response.status(403).json({
                    message: 'Forbidden: You do not have permission to access this endpoint'
                })
            }

            const errand = await Errand.findById(id);
            if(!errand) throw new Error('Errand not found')

            errand.status = 'complete'

            const completedErrand = await errand.save();
            response.json({
                message: 'Errand completed successfully',
                errand: completedErrand
            })
        })
    }catch(error){
        console.log(error);
        response.status(400).json({
            message: 'Error accepting errand',
            error: error.message
    })
    }
})

router.delete('/api/errands/:id', async (request, response) => {
    const {id} = request.params;

    const authHeader = request.headers['authorization']; 
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return response.status(401).json({
            message: 'Authorization header missing or improperly formatted',
        });
    }
    
    const token = authHeader.split(' ')[1];

    try {
        jwt.verify(token, Secret, async (error, decoded) => {
            if (error) throw new Error('Invalid Token');
    
            if (decoded.userRole !== 'user') {
                return response.status(403).json({
                    message: 'Forbidden: You do not have permission to access this endpoint',
                });
            }

            const errand = await Errand.findById(id);
            if (!errand) throw new Error('Errand not found');

            await errand.deleteOne();

            response.status(200).json({
                message: 'Errand deleted successfully',
            });
        });
    } catch (error) {
        console.log(error);
        response.status(500).json({
            message: 'Error deleting errand',
            error: error.message,
        });
    }
});


export default router;