import { v2 as cloudinary } from "cloudinary";
import fs from "fs";

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const uploadOnCloudinary = async (localFilePath) => {
    try {
        if(!localFilePath){
            console.error("Error in local file path!!")
            return  null
        }

        const response = await cloudinary.uploader.upload(localFilePath,{
            resource_type: "auto"
        })

        console.log("The file has been uploaded successfully - ", response.url)

        return response
    } catch (error) {
        fs.unlink(localFilePath)
        //removing locally saved temporary file as the update operation got failed
        return null
    }
}

export {uploadOnCloudinary}
