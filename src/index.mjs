import express from 'express';
import cors from 'cors'
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import {Chat} from './utils/schemas/schema.mjs'
import { Server } from 'socket.io';
import http from 'http'

import userRouter from './routes/users.mjs'
import authRouter from './routes/auth.mjs'
import errandRouter from './routes/errands.mjs'
import chatRouter from './routes/chats.mjs'
import adminRouter from './routes/admin.mjs'
import paymentRouter from './routes/payment.mjs'
import reviewRouter from './routes/review.mjs'
import notificationRouter from './routes/notification.mjs'
import dashboardRouter from './routes/dashboard.mjs'

dotenv.config();
const app = express();

const server = http.createServer(app);
const userSocketMap = new Map();


app.use(express.json());
app.use(cors({
    origin: 'http://localhost:3000', // Adjust this to your frontend's origin
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
}));

const {
    DB,
    PORT
} = process.env;

mongoose.connect(DB)
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

app.use(authRouter);

/*******************
 * 
 * USERS ENDPOINT
 * 
 ******************/

app.use(userRouter);

/*******************
 * 
 * ERRANDS ENDPOINT
 * 
 ******************/

app.use(errandRouter)

/*******************
 * 
 * ADMIN ENDPOINT
 * 
 ******************/

app.use(adminRouter);

/*******************
 * 
 * CHAT ENDPOINT
 * 
 ******************/

app.use(chatRouter);

/*******************
 * 
 * REVIEW ENDPOINT
 * 
 ******************/

app.use(reviewRouter)

/*******************
 * 
 * PAYMENT/WALLET ENDPOINT
 * 
 ******************/

app.use(paymentRouter);

/*******************
 * 
 * NOTIFICATION ENDPOINT
 * 
 ******************/

app.use(notificationRouter);

/*******************
 * 
 * DASHBOARD ENDPOINT
 * 
 ******************/

app.use(dashboardRouter);


// Initialize Socket.IO
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));

const io = new Server(server, {
    cors: {
        origin: '*', // Adjust this to your frontend's origin
        methods: ['GET', 'POST']
    }
});

// Handle Socket.IO connections
io.on('connection', (socket) => {
    console.log('User connected:', socket.id);

    socket.on('joinRoom', (data) => {
        const {room , userId} = data;

        userSocketMap.set(socket.id, userId);

        socket.join(room);
        console.log(`User ${socket.id} joined room: ${room}`);
    });

    // Listen for chat messages
    socket.on('send-message', async (data) => {
        const {message, errandId} = data;

        const userID = userSocketMap.get(socket.id);

        console.log('Message received from: ' + userID);

        try {
            const newMessage = new Chat({
                room: errandId,
                senderID: userID,
                message: message
            });

            await newMessage.save();
            console.log('Message Saved');

        } catch (error) {
            console.log('Error saving message:', error)
        }

        socket.broadcast.to(errandId).emit('receive-message', {message});
    });

    // Handle user disconnection
    socket.on('disconnect', () => {
        console.log('A user disconnected:', socket.id);
        userSocketMap.delete(socket.id);
    });
});