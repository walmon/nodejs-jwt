// Módulos requeridos
// Express levanta el servidor
var express    = require("express"), 
// jsonwebtoken permite firmar y verificar tokens firmados
// ¿Ver más? https://github.com/auth0/node-jsonwebtoken
	jwt = require("jsonwebtoken"),
// "driver" para mongodb
	mongoose = require("mongoose"),
// necesario por express para entender el cuerpo de las solicitudes web
	bodyParser = require("body-parser"),
// creación de servidor
	app = express();

// este es mi secreto para firmar sincrónicamente
// ¿Quieres sacar este key desde otras partes?
// https://github.com/auth0/node-jsonwebtoken
var privateKey = "thisisasupersecretkey!";

var port = process.env.PORT || 3001;

// Modelo que controla la comunicación con mongodb
// se encarga de "hashear" y agregar sal a la contraseña
var User = require('./models/user');
 
// Conectarse a la base de datos
mongoose.connect("mongodb://localhost/owasp");

// Configuraciones necesarias del servidor de Node.JS con Express
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// Para permitir solicitudes al API desde otros dominios
app.use(function(req, res, next) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST');
    res.setHeader('Access-Control-Allow-Headers', 'X-Requested-With,content-type, Authorization');
    next();
});

// endpoint para autenticar un usuario
app.post('/login', function(req, res) {
    User.findOne({email: req.body.email }, function(err, user) {
        if (err) {
            res.status(500).send({
                type: false,
                data: "Error occured: " + err
            });
        } else {
            if (user) {
                // autentica a través del modelo (mongoose) comparando la contraseña (posterior a hasharla) contra 
                // la contraseña hasheada en la db
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
// endpoint para registrar un usuario nuevo
app.post('/signin', function(req, res) {
	if(req.body == undefined || req.body.email == undefined || req.body.password == undefined){
		res.send(400);	
		return;
	}
    User.findOne({email: req.body.email, password: req.body.password}, function(err, user) {   
        if (err) {
            res.status(500).send("Ocurrió un error: " + err);
        } else {
            if (user) {
                res.status(409).send("El usuario ya existe en el sistema");
            } else {
                var userModel = new User();
                userModel.email = req.body.email;
                userModel.password = req.body.password;
                userModel.save(function(err, user) {
                	if(err) return res.status(500).send(err);
                	// Firmar el token 
                    var token = signToken({_id:user._id});
                    res.status(201).send({token:token}); 
                })
            }
        }
    });
});
// endpoint donde solicita un recurso privado
// ojo en ensureAuthorized
app.get('/me', ensureAuthorized, function(req, res) {
    // nunca retornarle al usuario o al cliente la sal o la contraseña "hasheada"
    User.findOne({_id: req.userid},'-salt -hashedPassword', function(err, user) {
        if (err) {
            res.status(500).send("Ocurrió un error: " + err);
        } else {
        	if(user == undefined) return res.status(404).send();
            res.status(200).send(user);
        }
    });
});

// Middleware para autenticación
function ensureAuthorized(req, res, next) {
    var bearerToken;
    // extrae el encabezado
    var bearerHeader = req.headers["authorization"];
    if (typeof bearerHeader !== 'undefined') {
        var bearer = bearerHeader.split(" ");
        if(bearer[1] == undefined) res.status(403).send();
        bearerToken = bearer[1];
        // verifica con el "secreto" si aún es un token JWT válido
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
// Para saber que el servidor está arriba
// Ingresar a http://localhost:3001
app.get('/', function(req, res) {
	res.status(200).send('Everything up and running');
});
process.on('uncaughtException', function(err) {
    console.log(err);
});

// Levanta el servidor
app.listen(port, function () {
    console.log( "Express server listening on port " + port);
});

// firma el token
function signToken (data){
    // ver más: https://github.com/auth0/node-jsonwebtoken
	return jwt.sign(data, privateKey, { expiresInMinutes: 1 });
}