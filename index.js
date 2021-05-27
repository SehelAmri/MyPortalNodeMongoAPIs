//import packages
var mongodb = require('mongodb');
var crypto = require('crypto');
var express = require('express');

var ObjectID = mongodb.ObjectID;

//CREATE FUNCTION TO RANDOM SALT
var genRandomString = function(length){
    return crypto.randomBytes(Math.ceil(length/2))
    .toString('hex')
    .slice(0,length);
}

var sha512 = function(password,salt){
 var hash = crypto.createHmac('sha512',salt);
hash.update(password);
var value = hash.digest('hex');
return{
    salt:salt,
    passwordHash:value
 };
}

function saltHashPassword(userPassword){
    var salt =  genRandomString(16);
    var passwordData = sha512(userPassword,salt);
   return passwordData;
}

function checkHashPassword(userPassword,salt){
    var passwordData = sha512(userPassword,salt);
    return passwordData;
}

//create Express Service
var app = express();
app.use(express.json());
app.use(express.urlencoded({extended:true}));

//create MongoDB Client
var MongoClient = mongodb.MongoClient;

//Connection URL
var url = 'mongodb://localhost:27017'

MongoClient.connect(url,{useNewUrlParser: true},function(err,client){
    if(err)
    console.log('Unable to connect',err);
    else{
        //register
        app.post('/register', (request,response,next) => {
          var post_data = request.body;

          var plaint_password = post_data.password;
          var hash_data = saltHashPassword(plaint_password);

          var password = hash_data.passwordHash;
          var salt = hash_data.salt;

          var name = post_data.name;
          var email = post_data.email;

          var insertJson = {
              'email': email,
              'password': password,
              'salt': salt,
              'name':name
          };
          var db = client.db('portalbase');

          //check email exists
          db.collection('user')
          .find({'email':email}).count(function(err,number){
              if(number != 0)
              {
                  response.json('Email already exists');
              }
              else{
                  //insert new user
                  if(plaint_password && email && name){
                  db.collection('user')
                  .insertOne(insertJson, function(error,res){
                    response.json('Registration Success!');
                  })
                }else{
                    response.json('please fill in  all the information');
                }
              }
          })
        })
        
        //Login
        app.post('/loginEmail', (request,response,next) => {
            var post_data = request.body;
           
            var email = post_data.email;
            var userPassword = post_data.password;
         
            var db = client.db('portalbase');
  
            //check email exists
            db.collection('user')
            .find({'email':email}).count(function(err,number){
                if(number == 0)
                {
                    response.json('User not available');
                }
                else{
                    //insert new user
                    db.collection('user')
                    .findOne({'email':email},function(error,user){
                     var salt  = user.salt;
                     if(userPassword != null){
                        var hashed_password = checkHashPassword(userPassword,salt).passwordHash;
                        var encrypted_password = user.password;
                       
                        if(hashed_password == encrypted_password){
                           response.json('Successfully logged in');
                        }else{
                           response.json('Incorrect Password');
                        }
                       }else{
                           response.json('dont leave password blank!');
                       }
                    })
                }
            })
          })
          app.post('/loginName', (request,response,next) => {
            var post_data = request.body;
           
            var name = post_data.name;
            var userPassword = post_data.password;
         
            var db = client.db('portalbase');
  
            //check name exists
            db.collection('user')
            .find({'name':name}).count(function(err,number){
                if(number == 0)
                {
                    response.json('User not available');
                }
                else{
                    //insert new user
                    db.collection('user')
                    .findOne({'name':name},function(error,user){
                     var salt  = user.salt;
                     if(userPassword != null){
                     var hashed_password = checkHashPassword(userPassword,salt).passwordHash;
                     var encrypted_password = user.password;
                    
                     if(hashed_password == encrypted_password){
                        response.json('Successfully logged in');
                     }else{
                        response.json('Incorrect Password');
                     }
                    }else{
                        response.json('dont leave password blank!');
                    }
                    })
                }
            })
          })
        //Start Web Server
        app.listen(3000,'172.16.11.101', () => {
            console.log('connected to MongoDB Server , WebService running on port 3000');
        })
    }
})
