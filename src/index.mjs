import express from 'express';
import cors from 'cors'
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import {User, Errand} from './utils/schemas/schema.mjs'

dotenv.config();
const app = express();

app.use(express.json());
app.use(cors());

const {
    PORT, 
    Secret
} = process.env;

var token;

mongoose.connect('mongodb://localhost:27017/campus-errand')
.then(() => console.log('MongoDB Connected'))
.catch(err => console.log(err));


app.get('/', (request, response) => {
    response.send('Welcome to Campus Errand API'); 
});

/*******************
 * 
 * AUTH ENDPOINT
 * 
 ******************/

app.post('/api/auth/register', async (request, response) => {
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

app.post('/api/auth/login', async (request, response) => {
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

app.get('/api/auth/me', async (request, response) => {
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

/*******************
 * 
 * USERS ENDPOINT
 * 
 ******************/

app.get('/api/users/:id', async (request,response) =>{
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

app.patch('/api/users/:id', async (request, response) => {
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

app.get('/api/runners', async (request, response) => {
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

/*******************
 * 
 * ERRANDS ENDPOINT
 * 
 ******************/

app.post('/api/errands', async (request, response) => {
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



            const userId = decoded.userId;


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

app.get('/api/errands', async (request, response) => {
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

app.get('/api/errands/available', async (request, response) => {
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

app.get('/api/errands/:id', async (request, response) => {
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

app.patch('/api/errands/:id/accept', async (request, response) => {
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

app.patch('/api/errands/:id/complete', async (request, response) => {
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

app.delete('/api/errands/:id', async (request, response) => {
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


/*******************
 * 
 * ADMIN ENDPOINT
 * 
 ******************/

app.get('/api/admin/requests', async (request, response) => {
    
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
        response.json({
            message: 'Error retrieving errands',
            error: error.message
        })
    }
})

app.get('/api/admin/users', async (request, response) => {
        
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

app.delete('/api/admin/users/:id', async (request, response) => {
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



app.listen(PORT, () => console.log(`Server running on port ${PORT}`));