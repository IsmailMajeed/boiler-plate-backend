import jwt from 'jsonwebtoken';
import { ApiError } from './ApiError.js';

// Function to extract token from cookies or headers
const extractToken = (req) => {
    // Check for token in cookies
    let token = req.cookies?.accessToken;

    // If not found in cookies, check in headers
    if (!token) {
        token = req.headers.authorization?.split(' ')[1];
    }

    return token;
};

// Function to fetch user ID from token
const loginUserId = (req) => {
    const token = extractToken(req);

    if (!token) {
        throw new ApiError(401, 'No token provided');
    }

    try {
        const decoded = jwt.decode(token);
        return decoded._id;
    } catch (error) {
        throw new ApiError(401, 'Invalid or expired token');
    }
};

export { loginUserId };
