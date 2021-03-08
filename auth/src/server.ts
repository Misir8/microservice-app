import express from 'express';
import {connect} from 'mongoose';
import {config} from 'dotenv';
import bodyParser from "body-parser";
import routes from "./route";

config();
const app = express();
const PORT = process.env.PORT || 5000;

connect(process.env.MONGO_URL || '', {
    useUnifiedTopology: true,
    useNewUrlParser: true
}).then(() => console.log('Successfully connected')).catch(err => console.log(err.message));

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

app.use('/api', routes);

app.listen(PORT, () => {
    console.log(`The application is listening on port ${PORT}!`);
});
