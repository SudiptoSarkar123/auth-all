

const bcrypt=require('bcryptjs')
const jwt=require('jsonwebtoken')

const hashPassword=(password)=>{
    const salt=10
    const hash=bcrypt.hashSync(password,salt)
    return hash

}

const comparePassword=(password,hash)=>{
    return bcrypt.compareSync(password,hash)
}


const AuthCheck=(req,res,next)=>{
    const token= req.body.token || req.query.token || req.headers['x-access-token']|| req.headers['authorization'];
    if(!token){
        return res.status(400).json({
            message:'Token is required for access this page'
        });
    }
    try{
        const decoded=jwt.verify(token,process.env.JWT_SECRECT)
        req.user=decoded;
       console.log('afetr login data',req.user);
    }catch(err){
       return res.status(400).json({
            message:'Invalid token access'
        });
    }
    return next();
}


module.exports={hashPassword,comparePassword,AuthCheck}