import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/apiError.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/apiResponse.js";
import jwt from 'jsonwebtoken'

const generateAccessAndRefreshTokens = async (userId) => {
  try {
    const user = await User.findById(userId);

    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    user.refreshToken = refreshToken;

    await user.save({ validateBeforeSave: false });

    return {accessToken, refreshToken}

  } catch (error) {
    throw new ApiError(
      500,
      "Something went wrong while generating refresh and access token"
    );
  }
};

const registerUser = asyncHandler(async (req, res) => {
  const { username, email, fullName, avatar, password, coverImage } = req.body;

  if (
    [fullName, email, username, password].some((params) => {
      return params?.trim() === "";
    })
  ) {
    throw new ApiError(400, "Some required field is empty!!");
  }

  const existingUser = await User.findOne({
    $or: [{ username }, { email }],
  });

  if (existingUser) {
    throw new ApiError(409, "User already exists with this username or email");
  }

  const avatarLocalPath = req.files?.avatar[0]?.path;
  // const coverImageLocalPath = req.files?.coverImage[0]?.path

  let coverImageLocalPath;

  if (
    req.files &&
    Array.isArray(req.files.coverImage) &&
    Array.length(req.files.coverImage) > 0
  ) {
    coverImageLocalPath = req.files.coverImage[0].path;
  }

  if (!avatarLocalPath) throw new ApiError(400, "Avatar is required!!");

  const avatarUpload = await uploadOnCloudinary(avatarLocalPath);
  const coverImageUpload = await uploadOnCloudinary(coverImageLocalPath);

  if (!avatarUpload) throw new ApiError(400, "Avatar is required!!");

  const user = await User.create({
    fullName,
    avatar: avatarUpload.url,
    coverImage: coverImageUpload?.url || "",
    email,
    password,
    username: username.toLowerCase(),
  });

  const userCreated = await User.findById(user._id).select(
    "-password -refreshToken"
  );

  if (!userCreated)
    throw new ApiError(
      500,
      "Something went wrong while registering the user!!"
    );

  return res
    .status(201)
    .json(new ApiResponse(200, userCreated, "User registered successfully!!"));
});

const loginUser = asyncHandler(async (req, res) => {
  const { email, username, password } = req.body;

  if (!email && !username) {
    throw new ApiError(400, "username and email is required!!");
  }

  const user = await User.findOne({
    $or: [{ username }, { email }],
  });

  if (!user) {
    throw new ApiError(404, " User does not exist!!");
  }

  const isPasswordValid = await user.isPasswordCorrect(password);

  if (!isPasswordValid) {
    throw new ApiError(401, "Invalid user Credentials!!");
  }

  const {accessToken, refreshToken} = await generateAccessAndRefreshTokens(user._id)

  const loggedInUser = await User.findById(user._id).select("-password -refreshToken")
  
  const options = {
    httpOnly: true,
    secure: true
  }

  return res.status(200)
            .cookie("accessToken",accessToken, options)
            .cookie("refreshToken",refreshToken,options)
            .json(
                new ApiResponse(200,
                    {
                        user: loggedInUser, accessToken, refreshToken
                    },
                    "User logged In Successfully"
                )
            )

});

const logOutUser = asyncHandler( async (req,res) => {
    await User.findByIdAndUpdate(req.user._id, {
            $set: {
                refreshToken: undefined,
            },
        },
        {
            new: true
        }

    )

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .clearCookie("accessToken",options)
    .clearCookie("refreshToken",options)
    .json(new ApiResponse(200, {} , "User logged out successfully!" ))

})

const refreshAccessToken = asyncHandler(async (req,res) => {
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken

    if(!incomingRefreshToken){
        throw new ApiError(401,"Unauthorized Request!!")
    }
    
    try {
        const decodedToken = jwt.verify(incomingRefreshToken,process.env.REFRESH_TOKEN_SECRET)
        
        const user = await User.findById(decodedToken._id)
    
        if(!user){
            throw new ApiError(401, "Invalid refresh token")
        }
    
        if(incomingRefreshToken !== user?.refreshToken){
            throw new ApiError(401, "Refreshtoken is expired or used")
        }
    
        const options = {
            httpOnly:true,
            secure: true
        }
    
        const {accessToken,refreshToken} = await generateAccessAndRefreshTokens(user._id)
    
        return res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken",refreshToken, options)
        .json(
            new ApiResponse(
                200,
                {accessToken,refreshToken},
                "Access token refreshed!!"
            )
        )
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid refresh token")
    }

})

const changeCurrentPassword = asyncHandler( async (req,res) => {
  const {oldPassword , newPassword} = req.body

  const user = await User.findById(req.user?._id)

  const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)

  if(!isPasswordCorrect){
    throw new ApiError(401,"The old password is incorrect!!")
  }

  if(oldPassword === newPassword){
    throw new ApiError(400,"Old and New password can not be same!")
  }

  user.password = newPassword
  await user.save({validateBeforeSave:false})

  return res
  .status(200)
  .json(new ApiResponse(200,{}, "Password changed successfully!!"))

})

const getCurrentUser = asyncHandler( async (req,res) => {
  return res
  .status(200)
  .json(new ApiResponse(200,req.user,"current user fetched successfully!!"))
})

const updateAccountDetails = asyncHandler( async(req,res) => {
  const {fullName, email} = req.body

  if(!fullName || !email){
    throw new ApiError(400, "All fields are required!!")
  }

  const user = await User.findByIdAndUpdate(
    req.user?._id,
    {
      $set: {
        fullName,
        email
      }
    },
    {
      new: true
    }
  ).select("-password")

  return res
  .status(200)
  .jso(new ApiResponse(200,user,"Account details updated successfully"))

})

const updateUserAvatar = asyncHandler(async(req,res) => {
  const {newCoverImageLocalPath} = req.file?.path

  if(newCoverImageLocalPath){
    throw new ApiError(400,"new Avatar file is missing!!")
  }

  const avatar = await uploadOnCloudinary(newCoverImageLocalPath)

  if(avatar.url){
    throw new ApiError(500,"Error while uploading avatar file!!")
  }

  const user = await User.findByIdAndUpdate(
    req.user._id,
    {
      $set: {
        avatar : avatar.url,
      }
    },
    {
      new:true
    }
  ).select("-password")

  return res
  .status(200)
  .json(new ApiResponse(200,user,"Avatar updated successfully!!"))

})

const updateUserCoverImage = asyncHandler(async(req,res) => {
  const {newCoverImageLocalPath} = req.file?.path

  if(newCoverImageLocalPath){
    throw new ApiError(400,"new Cover Image file is missing!!")
  }

  const coverImage = await uploadOnCloudinary(newCoverImageLocalPath)

  if(coverImage.url){
    throw new ApiError(500,"Error while uploading coverImage file!!")
  }

  const user = await User.findByIdAndUpdate(
    req.user._id,
    {
      $set: {
        coverImage: coverImage.url,
      }
    },
    {
      new:true
    }
  ).select("-password")

  return res
  .status(200)
  .json(new ApiResponse(200,user,"CoverImage updated successfully!!"))

})

export { registerUser, loginUser, logOutUser, refreshAccessToken, changeCurrentPassword, getCurrentUser,updateAccountDetails, updateUserAvatar, updateUserCoverImage };
