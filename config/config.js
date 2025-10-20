 const config = {
 env: process.env.NODE_ENV || 'development', 
 port: process.env.PORT || 3000,
 jwtSecret: process.env.JWT_SECRET || "YOUR_secret_key", 
 mongoUri: process.env.MONGODB_URI ||"mongodb+srv://Cluster42309:aGefZazvybFoK2md@cluster42309.kwh5xdf.mongodb.net/Portfolio?retryWrites=true&w=majority&appName=Cluster42309"||
 process.env.MONGO_HOST ||
 'mongodb://' + (process.env.IP || 'localhost') + ':' + 
(process.env.MONGO_PORT || '27017') +
 '/mernproject' 
 }
 export default config