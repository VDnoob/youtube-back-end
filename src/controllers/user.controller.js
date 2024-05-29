import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/apiError.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from '../utils/cloudinary.js'
import { ApiResponse } from "../utils/apiResponse.js";

const registerUser = asyncHandler(async (req, res) => {

    const { username, email, fullName, avatar, password, coverImage } = req.body;

    if (
        [fullName, email, username, password].some((params) => {
        return params?.trim() === "";
        })
    ) {
        throw new ApiError(400, "Some required field is empty!!");
    }

    const existingUser = await User
                        .findOne({
                            $or: [{ username }, { email }],
                        })

    if (existingUser) {
        throw new ApiError(409,"User already exists with this username or email")
    }

    const avatarLocalPath = req.files?.avatar[0]?.path
    // const coverImageLocalPath = req.files?.coverImage[0]?.path

    let coverImageLocalPath;

    if(req.files && Array.isArray(req.files.coverImage) && Array.length(req.files.coverImage) > 0){
        coverImageLocalPath = req.files.coverImage[0].path
    }

    if(!avatarLocalPath) throw new ApiError(400, "Avatar is required!!")
        

    const avatarUpload = await uploadOnCloudinary(avatarLocalPath)
    const coverImageUpload = await uploadOnCloudinary(coverImageLocalPath)

    if(!avatarUpload) throw new ApiError(400, "Avatar is required!!")
    
    const user = await User.create({
        fullName,
        avatar: avatarUpload.url,
        coverImage: coverImageUpload?.url || "",
        email,
        password,
        username: username.toLowerCase(),
    })
    
    const userCreated = await User.findById(user._id).select(
        "-password -refreshToken"
    )

    if(!userCreated) throw new ApiError(500, "Something went wrong while registering the user!!")

    return res.status(201).json(new ApiResponse(200, userCreated, "User registered successfully!!"))

});

export { registerUser };
