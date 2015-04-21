// Required Modules
var express    = require("express"), 
	morgan = require("morgan"), 
	jwt = require("jsonwebtoken"),
	mongoose = require("mongoose"),
	bodyParser = require("body-parser"),
	app = express();
var privateKey = "thisisasupersecretkey!";

var port = process.env.PORT || 3001;
var User = require('./models/user');
 
// Connect to DB
mongoose.connect("mongodb://localhost/owasp");
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(morgan("dev"));
app.use(function(req, res, next) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST');
    res.setHeader('Access-Control-Allow-Headers', 'X-Requested-With,content-type, Authorization');
    next();
});

app.post('/login', function(req, res) {
    User.findOne({email: req.body.email }, function(err, user) {
        if (err) {
            res.status(500).send({
                type: false,
                data: "Error occured: " + err
            });
        } else {
            if (user) {
            	if(!user.authenticate(req.body.password)){
            		return res.status(403).send();
            	}
            	var token = signToken({_id:user._id});
               res.status(200).send({token: token}); 
            } else {
                res.status(403).send("Incorrect email/password");    
            }
        }
    });
});

app.post('/signin', function(req, res) {
	if(req.body == undefined || req.body.email == undefined || req.body.password == undefined){
		res.send(400);	
		return;
	}
    User.findOne({email: req.body.email, password: req.body.password}, function(err, user) {
        
        if (err) {
            res.send(500).json({
                type: false,
                data: "Ocurrió un error: " + err
            });
        } else {
            if (user) {
                res.send(409).json({
                    type: false,
                    data: "El usuario ya existe en el sistema"
                });
            } else {
                var userModel = new User();
                userModel.email = req.body.email;
                userModel.password = req.body.password;
                userModel.save(function(err, user) {
                	if(err) return res.status(500).send(err);
                	// sign the token
                    var token = signToken({_id:user._id});

                    res.status(201).send({token:token});
                    
                })
            }
        }
    });
});

app.get('/me', ensureAuthorized, function(req, res) {
    User.findOne({_id: req.userid},'-salt -hashedPassword', function(err, user) {
        if (err) {
            res.status(500).send("Ocurrió un error: " + err);
        } else {
        	if(user == undefined) return res.status(404).send();
        	console.log(user);
            res.status(200).send(user);
        }
    });
});
app.get('/private-information', ensureAuthorized, function(req,res){
	res.status(200).send('Este es un recurso protegido');
});
function ensureAuthorized(req, res, next) {
    var bearerToken;
    var bearerHeader = req.headers["authorization"];
    if (typeof bearerHeader !== 'undefined') {
        var bearer = bearerHeader.split(" ");
        if(bearer[1] == undefined) res.status(403).send();
        bearerToken = bearer[1];

        jwt.verify(bearerToken, privateKey, function(err, decoded){
        	if(err){
        		res.status(403).send();
        	}else{
        		console.log(decoded);
        		req.userid = decoded._id;
        		next();
        	}
        });
    } else {
        res.status(403).send();
    }
}
app.get('/', function(req, res) {
	res.status(200).send('Everything up and running');
});
process.on('uncaughtException', function(err) {
    console.log(err);
});
app.listen(port, function () {
    console.log( "Express server listening on port " + port);
});

function signToken (data){
	return jwt.sign(data, privateKey, { expiresInMinutes: 1 });
}