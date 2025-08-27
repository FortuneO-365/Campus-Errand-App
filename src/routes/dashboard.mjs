import {Router} from 'express';
import {User, Errand, Wallet} from '../utils/schemas/schema.mjs'
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import { promisify } from 'util';

dotenv.config();
const router = Router();

const verifyToken = promisify(jwt.verify);
const { Secret } = process.env;

router.get('/api/dashboard/summary', async (request, response) => {
    const authHeader = request.headers['authorization'];

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return response.status(401).json({
            message: 'Authorization header missing or improperly formatted',
        });
    }

    const token = authHeader.split(' ')[1];

    try {
        if (!token) throw new Error('No token Provided');

        const decoded = await verifyToken(token, Secret);

        let dashboardData = {};

        if (decoded.userRole === 'admin') {
            const [totalUsers, runners, users, tasksCreated, balanceDetails] = await Promise.all([
                User.find(),
                User.find({ role: 'runner' }),
                User.find({ role: 'user' }),
                Errand.find({ userId: decoded.userId }),
                Wallet.findOne({ userID: decoded.userId }),
            ]);

            dashboardData = {
                message: 'Dashboard details retrieved successfully',
                totalUsers: totalUsers.length,
                noOfRunners: runners.length,
                noOfUsers: users.length,
                createdTasks: tasksCreated.map(task => ({
                    title: task.title,
                    description: task.description,
                    status: task.status,
                    price: task.price,
                    pickupLocation: task.pickupLocation,
                    dropoffLocation: task.dropoffLocation,
                    runnerId: task.runnerId,
                })),
                balance: balanceDetails?.balance || 0,
            };
        } else if (decoded.userRole === 'runner') {
            const [tasksCreated, tasksAccepted, balanceDetails] = await Promise.all([
                Errand.find({ userId: decoded.userId }),
                Errand.find({ runnerId: decoded.userId }),
                Wallet.findOne({ userID: decoded.userId }),
            ]);

            dashboardData = {
                message: 'Dashboard details retrieved successfully',
                noOfTasksCreated: tasksCreated.length,
                noOfTasksAccepted: tasksAccepted.length,
                createdTasks: tasksCreated.map(task => ({
                    title: task.title,
                    description: task.description,
                    status: task.status,
                    price: task.price,
                    pickupLocation: task.pickupLocation,
                    dropoffLocation: task.dropoffLocation,
                    runnerId: task.runnerId,
                })),
                tasksAccepted: tasksAccepted.map(task => ({
                    userId: task.userId,
                    title: task.title,
                    description: task.description,
                    status: task.status,
                    price: task.price,
                    pickupLocation: task.pickupLocation,
                    dropoffLocation: task.dropoffLocation,
                })),
                balance: balanceDetails?.balance || 0,
            };
        } else if (decoded.userRole === 'user') {
            const tasksCreated = await Errand.find({ userId: decoded.userId });

            const acceptedTasks = tasksCreated.filter(task => task.status === 'accepted');
            const completedTasks = tasksCreated.filter(task => task.status === 'complete');

            dashboardData = {
                message: 'Dashboard details retrieved successfully',
                noOfTasksCreated: tasksCreated.length,
                noOfTasksAccepted: acceptedTasks.length,
                noOfTasksCompleted: completedTasks.length,
                createdTasks: tasksCreated.map(task => ({
                    title: task.title,
                    description: task.description,
                    status: task.status,
                    price: task.price,
                    pickupLocation: task.pickupLocation,
                    dropoffLocation: task.dropoffLocation,
                    runnerId: task.runnerId,
                })),
            };
        }

        return response.json(dashboardData);
    } catch (error) {
        console.error(error);
        return response.status(400).json({
            message: 'Error retrieving Dashboard',
            error: error.message,
        });
    }
});


router.get('/api/dashboard/recent', async (request, response) => {
    const authHeader = request.headers['authorization'];

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return response.status(401).json({
            message: 'Authorization header missing or improperly formatted',
        });
    }

    const token = authHeader.split(' ')[1];
})
export default router;