import { asyncHandler } from '../utils/asyncHandler.js';
import { ApiError } from '../utils/ApiError.js';
import { ApiResponse } from '../utils/ApiResponse.js';
import { User } from '../Models/userManagement.model.js';
import { loginUserId } from '../utils/authUtils.js';


const generateAccessAndRefereshTokens = async (userId) => {
    try {
        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        user.refreshToken = refreshToken
        await user.save({ validateBeforeSave: false })

        return { accessToken, refreshToken }

    } catch (error) {
        throw new ApiError(500, "Somthing went wrong while genrating refresh and access token")
    }
}

const registerUser = asyncHandler(async (req, res) => {
    const { email, phone, password } = req.body;

    if (!email || !phone || !password) {
        throw new ApiError(400, 'Please provide all required fields');
    }

    const user = await User.findOne({ email, phone });

    if (user) {
        if (user.otp.verified) {
            throw new ApiError(400, 'User already exists and is verified');
        } else {
            user.password = password;
            await user.save();
            return res.status(200).json(
                new ApiResponse(200, user, 'Password updated successfully for unverified user')
            );
        }
    } else {
        const newUser = await User.create({
            email,
            phone,
            password
        });

        if (newUser) {
            return res.json(
                new ApiResponse(201, newUser, 'User registered successfully')
            );
        } else {
            throw new ApiError(400, 'Invalid user data');
        }
    }
});


const logoutUser = asyncHandler(async (req, res) => {
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: { refreshToken: undefined }
        },
        { new: true }
    )

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
        .status(200)
        .clearCookie("accessToken", options)
        .clearCookie("refreshToken", options)
        .json(new ApiResponse(200, {}, "User logged Out"))

})

const loginUser = asyncHandler(async (req, res) => {
    const { contact, password } = req.body;

    if (!contact || !password) {
        throw new ApiError(400, "Contact and password are required");
    }

    console.log('Contact:', contact); // Debugging log
    let user;
    if (/^\S+@\S+\.\S+$/.test(contact)) { // Email regex
        user = await User.findOne({ email: contact });
    } else if (/^\+?\d{10,15}$/.test(contact)) {
        user = await User.findOne({ phone: contact });
    } else {
        throw new ApiError(400, 'Invalid email or phone number format');
    }

    if (!user) {
        throw new ApiError(404, "User does not exist");
    }

    const isPasswordValid = await user.isPasswordCorrect(password);
    if (!isPasswordValid) {
        throw new ApiError(401, "Invalid user credentials");
    }

    const { accessToken, refreshToken } = await generateAccessAndRefereshTokens(user._id);

    const loggedInUser = await User.findById(user._id).select("-password -refreshToken");

    const isProduction = process.env.NODE_ENV === 'production';

    const accessTokenExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 1 day
    const refreshTokenExpiry = new Date(Date.now() + 3 * 24 * 60 * 60 * 1000); // 3 days

    const cookieOptions = {
        httpOnly: true,
        secure: isProduction, // Set secure flag to true in production
        sameSite: 'None'
    };

    res
        .cookie("accessToken", accessToken, { ...cookieOptions, expires: accessTokenExpiry })
        .cookie("refreshToken", refreshToken, { ...cookieOptions, expires: refreshTokenExpiry })
        .setHeader('accessToken', accessToken)
        .setHeader('refreshToken', refreshToken)
        .json(
            new ApiResponse(
                200,
                { user: loggedInUser, accessToken, refreshToken },
                "User logged In Successfully"
            )
        );
});

const changeCurrentPassword = asyncHandler(async (req, res) => {
    const { newPassword } = req.body;
    const userId = loginUserId(req);

    const user = await User.findById(userId).select("-password -refreshToken");;
    if (!user) {
        throw new ApiError(404, 'User not found');
    }

    if (!user.otp.verified) {
        throw new ApiError(400, "Please verify your OTP to change password")
    }

    user.password = newPassword;
    await user.save();

    res.json(new ApiResponse(
        200, { user }, "Password changed successfully"
    ));
});


export {
    registerUser,
    loginUser,
    logoutUser,
    changeCurrentPassword,
};
