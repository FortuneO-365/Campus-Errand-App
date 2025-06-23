import mongoose from "mongoose"
import bcrypt from "bcryptjs";
import { type } from "os";

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
        unique: true,
    },
    password: {
        type: String,
        required: true,
    },
    role: {
        type: String,
        enum: ['admin', 'user', 'runner'],
        default: 'user',
    },
},{timestamps: true})

const errandSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'users',
    },
    title: {
        type: String,
        required: true,
    },
    description: {
        type: String,
        required: true,
    },
    pickupLocation: {
        type: String,
        required: true,
    },
    dropoffLocation: {
        type: String,
        required: true,
    },
    price: {
        type: String,
        required: true,
    },
    runnerId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'users',
        default: null,
    },
    status: {
        type: String,
        enum: ['available', 'accepted', 'complete'],
        default: 'available',
    },
    
},{timestamps: true})

const chatSchema = new mongoose.Schema({
    room: {
        type: String,
        required: true
    },
    senderID: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'users'
    },
    errandId: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'errands'
    },
    message: {
        type: String,
        required: true,
    }
},{timestamps:true})

const reviewSchema = new mongoose.Schema({
    userID: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'users'
    },
    runnerID: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'users',
    },
    rating: {
        type: String,
        required: true,
    },
})

const walletSchema = new mongoose.Schema({
    userID: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'users',
    },
    balance: {
        type: Number,
        required: true,
        default: 0.00,
    }
},{timestamps: true});

const transactionSchema = new mongoose.Schema({
    senderID: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'users'
    },
    receipientID: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'users'
    },
    amount: {
        type: Number,
        required: true,
    },
    description: {
        type: String,
        default: null,
    },
    status: {
        type: String,
        enum: ['accepted', 'verified'],
        default: 'accepted'
    }
},{timestamps: true});

const notificationSchema = new mongoose.Schema({
    userID: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'users'
    },
    header: {
        type: String,
        required: true,
    },
    message: {
        type: String,
        required: true,
    },
    status:{
        type: String,
        enum: ['unread', 'read'],
        default: 'unread'
    }
},{timestamps: true})

errandSchema.pre('save', function(next) {
    if (this.status !== 'accepted') {
        this.runnerId = null;
    }
    next();
});

userSchema.pre('save', async function(next) {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
})

export const User = mongoose.model('User', userSchema, 'users');
export const Errand = mongoose.model('Errand', errandSchema, 'errands');
export const Chat = mongoose.model('Chat', chatSchema,' chats');
export const Review = mongoose.model('Review', reviewSchema, 'reviews');
export const Wallet = mongoose.model('Wallet', walletSchema, 'wallet');
export const Transaction = mongoose.model('Transaction', transactionSchema, 'transactions');
export const Notification = mongoose.model('Notifications',notificationSchema, 'notifications');