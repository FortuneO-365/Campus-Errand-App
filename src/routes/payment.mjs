import {Router} from 'express';
import {Wallet} from '../utils/schemas/schema.mjs'
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';

dotenv.config();
const router = Router();

const { Secret } = process.env;

router.get('/api/wallet', async (request, response) => {
    const {userId} = request.query;
    const authHeader = request.headers['authorization']; 

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return response.status(401).json({
            message: 'Authorization header missing or improperly formatted',
        });
    }
    
    const token = authHeader.split(' ')[1];
    try {
        if(!userId) return response.status(401).json({message:'User ID not found'});
        if(!token) return response.status(401).json({message:'No token Provided'});

        jwt.verify(token, Secret, async ( error, decoded) => {
            if (error) return response.status(401).json({message:'Invalid Token'});

            if(decoded.userId !== userId || decoded.userRole !== 'admin'){
                return response.status(403).json({
                    message: 'Forbidden: You do not have permission to access this endpoint',
                });
            }

            const wallets = await Wallet.find({userID: userId})
            const balance = wallets.map(wallet => wallet.balance);

            response.json({
                message: 'Wallet Balance retrieved Successfully',
                amount: balance,
            })
        })

    } catch (error) {
        console.log(error);
        response.status(400).json({
            message: 'Error retrieving Wallet Balance',
            error: error.message,
        })
    }

})

router.get('/api/wallet/history', async (request, response) => {
    const {userId} = request.query;
    const authHeader = request.headers['authorization']; 

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return response.status(401).json({
            message: 'Authorization header missing or improperly formatted',
        });
    }
    
    const token = authHeader.split(' ')[1];
    try {
        if(!userId) return response.status(401).json({message:'User ID not found'});
        if(!token) return response.status(401).json({message:'No token Provided'});

        jwt.verify(token, Secret, async ( error, decoded) => {
            if (error) return response.status(401).json({message:'Invalid Token'});

            if(decoded.userId !== userId || decoded.userRole !== 'admin'){
                return response.status(403).json({
                    message: 'Forbidden: You do not have permission to access this endpoint',
                });
            }

            // let transactions = oi
        })
    }catch(error){
        
    }
})

export default router;