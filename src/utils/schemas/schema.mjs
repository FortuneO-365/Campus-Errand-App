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
        type: String,
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
        type: String,
        ref: 'users',
        default: null,
    },
    status: {
        type: String,
        enum: ['available', 'accepted', 'complete'],
        default: 'available',
    },
    
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