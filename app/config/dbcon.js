const mongoose = require('mongoose')
const employeeCon = async ()=>{
    try {
        const dbCon = await mongoose.connect(process.env.MONGO_URI)
        console.log('Database connected...');
        
    } catch (error) {
        console.log('Database failed to connected ...!',error);
                
    }
}

module.exports = employeeCon ;