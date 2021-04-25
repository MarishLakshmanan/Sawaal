require("dotenv").config();
const express = require("express");
const ejs = require("ejs");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const app = express();
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const { Passport } = require("passport");
const session = require("express-session");
const findOrCreate = require("mongoose-findorcreate");
const GoogleStrategy = require("passport-google-oauth2").Strategy;
const flash = require("express-flash");
const nodemailer = require("nodemailer");
const {google} = require("googleapis");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
var fs = require('fs');
const schedule = require("node-schedule");
const { log } = require("console");

const oAuthClient = new google.auth.OAuth2(process.env.MAIL_CLIENT_ID,process.env.MAIL_CLIENT_SECRET,process.env.MAIL_REDIRECT_URI);
oAuthClient.setCredentials({refresh_token:process.env.MAIL_REFRESH_TOKEN});

const storage = multer.diskStorage({
    destination:"./public/uploads/",
    filename:(req,file,cb) =>{
        cb(null,file.fieldname+"-"+Date.now()+path.extname(file.originalname));
    }
})

const upload = multer({
    storage:storage,
    limits:{fileSize:15000000},
    fileFilter:(req,file,cb)=>{
        const fileTypes = /jpeg|jpg|png/;
        const extname = fileTypes.test(path.extname(file.originalname).toLowerCase());
        const mime = fileTypes.test(file.mimetype);

        if(mime && extname){
            return cb(null,true);
        }else{
            return cb("You can only upload jpeg/jpg/png images")
        }
    }
}).single("userImage");

app.use(express.static("public"));
app.use(express.urlencoded({extended:true}));
app.set('view engine','ejs');

app.use(flash());
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
  }))

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb+srv://admin-marish:"+process.env.MONGODB_PASSWORD+"@sawaaldb.oex9q.mongodb.net/SawaalDB",{useNewUrlParser:true});


function createChallenge(name,posted,totalDays,remainingDays,completedDays){
    this.challengeName = name;
    this.posted = posted;
    this.totalDays = totalDays;
    this.remainingDays = remainingDays;
    this.completedDays = completedDays; 
}

function createPosts(title,description,date,day){
    this.postTitle = title;
    this.postDescription  = description;
    this.postDate = date;
    this.postDay = day;
};

const postSchema = new mongoose.Schema({
    postTitle:String,
    postDescription:String,
    username:String,
    postDay:Number,
    userID:String,
    imgUrl:String,
    image:{
        data:Buffer,
        contentType:String
    }
});

const userSchema = new mongoose.Schema({
    username:String,
    email:String,
    Bio:String,
    image:{
        data:Buffer,
        contentType:String
    },
    imgUrl:String,
    Badges:Number,
    postLink:[Object],
    challenges:Object,
    completedChallenges:[String],
    googleId:String,
    challengeCompleted:Boolean,
    posted:Boolean,
    challengeDropped:Number
});



userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const UserModel = new mongoose.model("Users",userSchema);
const PostModel = new mongoose.model("Posts",postSchema);

passport.use(UserModel.createStrategy());


passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
passport.deserializeUser(function(id, done) {
    UserModel.findById(id, function(err, user) {
      done(err, user);
    });
});

passport.use(new GoogleStrategy({
    clientID:     process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/login",
    passReqToCallback   : true,

  },
  function(request, accessToken, refreshToken, profile, done) {

    UserModel.findOne({googleId:profile.id},function(err,user){
        if(err){
            return done(err);
        }else{
            if(user){
                return done(null,user);
            }else{
                user = new UserModel({
                    googleId: profile.id,
                    email:profile.email,
                    username:(profile.given_name+" "+profile.family_name),
                    imgUrl:profile.picture,
                    challengeCompleted:false
                });

                user.save(function(error){
                    if(error){
                        console.log(error);
                    }else{
                        return done(null,user);
                    }
                });
            }
        }
    })
    
  }
));

app.get("/",(req,res)=>{
    if(req.isAuthenticated()){
    res.render("home",{user:req.user,owner:true});
    }else{
        
        res.render("login");
    }
});

app.get("/community/:userID",(req,res)=>{
    const id = req.params.userID;
    if(req.isAuthenticated()){
        UserModel.findOne({_id:id},function(err,user){
            if(err){
                console.log(err);
            }else{
                if(user){
                    res.render("home",{user:user,owner:false})
                }else{
                    res.render("show-messages",{message:"You can't access this page for now please try again later"})
                }
            }
        });
    }
});

app.get("/logout",(req,res)=>{
    if(req.isAuthenticated()){
        req.logOut();
        res.redirect("/login");
    }else{
        res.render("show-messages",{message:"You are not logged in 👮‍♂️"})
    }
})

app.get("/community",(req,res)=>{
    if(req.isAuthenticated()){
        PostModel.find(function(err,users){
            if(err){
                res.render("show-messages",{message:err.message});
            }else{
                res.render("community",{users:users});
            }
        })
       
    }else{
        res.redirect("/login");
    }
});

app.get("/edit-user",(req,res)=>{
    if(req.isAuthenticated()){
        res.render("edit-user",{msg:undefined});
    }else{
        res.redirect("/login");
    }
});

app.get("/delete-challenge",(req,res)=>{
    if(req.isAuthenticated()){
        UserModel.findOneAndUpdate({_id:req.user._id},{challenges:{},postLink:[]},function(err){
            if(err){
                console.log(err);
                res.render("send-message",{message:"There is an error please try after"})
            }else{
                console.log("Deleted");
                res.redirect("/");
            }
            
        })
    }else{
        res.redirect("/login");
    }
})

app.get("/login",(req,res)=>{
    res.render("login");
})

app.get("/sign-up",(req,res)=>{
    res.render("sign-up");
})

app.get('/auth/google/',
  passport.authenticate('google', { scope:
      [ 'email', 'profile' ] }
));

app.get( '/auth/google/login',
    passport.authenticate( 'google', { failureRedirect: '/login'}),function(req,res){
        res.redirect("/");
});

app.get("/change-password/:UserID/:token",(req,res)=>{

    const userID = req.params.UserID;
    const token = req.params.token;

    if(userID){
        UserModel.findOne({_id:userID},function(err,user){
            if(err){
                console.log(err);
                res.render("show-messages",{message:"You are not authoried 👮‍♂️"});
            }else{
                if(user){
                    const secret = process.env.PASSWORD_RESET_SECRET+user.hash;
                    try{
                        const payload = jwt.verify(token,secret);
                        res.render("change-password",{userID:req.params.UserID});
                    }catch(e){
                        console.log(e);
                        res.render("show-messages",{message:err.message});
                    }
                }else{
                    res.render("show-messages",{message:"No User Found 💔"});   
                }
            }
        })
    }else{
        console.log("error");
    }
    
});

app.get("/about",(req,res)=>{
    res.render("about");
})


app.post("/sign-up",(req,res)=>{
   const name = req.body.username;
   const email = req.body.email;
   const password = req.body.password;

   UserModel.register({username:name},password,function(err,user){
       if(err){
           console.log(err);
           res.redirect("/sign-up");
       }else{
           passport.authenticate("local")(req,res,function(){
               user.email = email;
               user.challengeCompleted=false;
               user.save();
               res.redirect("/");
           })
       }
   });
});

app.post("/login",(req,res)=>{
    const username = req.body.username;
    const password = req.body.password;

    const user = new UserModel({
        username:username,
        password:password
    });

    req.login(user,function(err){
        if(err){
            alert("Username or Password is wrong");
        }else{
            passport.authenticate("local",{failureRedirect:"/login",failureFlash:true})(req,res,function(err){
                if(err){
                    console.log(err);
                }else{
                    res.redirect("/");
                }
            })
            
        }
    })
});

app.post("/change-password/:UserID/:token",(req,res)=>{
    const userID = req.params.UserID;
    const password = req.body.password;
    UserModel.findOne({_id:userID},function(err,user){
        if(err){
            console.log(err);
        }else{
            user.setPassword(password,function(err){
                if(err){
                    console.log(err);
                }else{
                    user.save();
                    res.redirect("/login");
                }
            })
        }
    })
});

app.post("/forgot-password",(req,res) => {
    const email = req.body.email;
    var userID;
    UserModel.findOne({email:email},function(err,user){
        if(err){
            console.log(err);
        }else{
            if(user){
                if(user.googleId){
                    res.render("show-messages",{message:"You have logged in using your google account use the log in with google button on the login page to login"})
                }
                userID=user._id;
                const secret = process.env.PASSWORD_RESET_SECRET+user.hash;
                const payload = {user:userID};
                const token = jwt.sign(payload,secret,{expiresIn:"10m"});
                sendMail(userID,token).then((result) => console.log("Email sent....",result))
                .catch((error) => console.log(error.message));
                res.render("show-messages",{message:"Please Check your mailbox 💌 for password reset link"});
            }else{
                res.render("show-messages",{message:"Your Email-id does not exist 💔"});
            }
        }
    });
    
});

app.post("/create-challenge",(req,res)=>{
    const name = req.body.challengeName;
    const duration = parseInt(req.body.challengeDuration);

    const Challenge = {challengeName:name,totalDays:duration,remainingDays:duration-1,completedDays:1};
    if( req.user.challenges && Object.keys(req.user.challenges).length>0){
        res.render("show-messages",{message:"You have an ongoing Challenge Complete it first don't give up 💪"})
    }else{

        if(req.user.challengeCompleted){
            req.user.challengeCompleted=false;
        }

        req.user.challenges = Challenge;
        req.user.save(function(err){
            res.redirect("/");
        })
    }
});

app.post("/create-post",(req,res)=>{

    if(!req.user){
        res.redirect("/login");
        return;
    }

    const title = req.body.postTitle;
    const description = req.body.postText;
    const postDate = new Date().toDateString();
    const day = req.user.challenges.completedDays;

    if(req.user.challengeDropped==1){
        req.user.challengeDropped=0;
    }

    const Post = new createPosts(title,description,postDate,day);
    const communityPost = new PostModel({
        postTitle:title,
        postDescription:description,
        username:req.user.username,
        postDay:day,
        userID:req.user._id,
        imgUrl:req.user.imgUrl,
        image:req.user.image
    });

    console.log(communityPost);

    req.user.posted=true;

    req.user.postLink.unshift(Post);
    req.user.save((err)=>{
        communityPost.save();
        // console.log(req.user);
        res.redirect("/");
    })
});

app.post("/edit-user",(req,res)=>{
   upload(req,res,(err)=>{
       if(err){
           res.render("edit-user",{msg:err})
       }else{
           req.user.username = req.body.username;
           req.user.Bio = req.body.userBio;
           if(req.file!=undefined){
                req.user.image.data = fs.readFileSync(__dirname+'/public/uploads/'+req.file.filename);
                req.user.image.contentType = req.file.mimetype;
           }
           req.user.save(function(err){
            if(req.file!=undefined){
                fs.unlink(__dirname+"/public/uploads/"+req.file.filename,()=>{
                    console.log("success");
                });
             }
            res.redirect("/");
           });
       }
   });
});

app.listen(process.env.PORT || 3000,()=>{
    console.log("Connected to port 3000");
})

async function sendMail(userID,token){

    const accessToken = await oAuthClient.getAccessToken();

    const transport = nodemailer.createTransport({
        service:"gmail",
        auth:{
            type:"OAuth2",
            user:"techsakthi936@gmail.com",
            clientId:process.env.MAIL_CLIENT_ID,
            clientSecret:process.env.MAIL_CLIENT_SECRET,
            refreshToken:process.env.MAIL_REFRESH_TOKEN,
            accessToken:accessToken
        }
    });

    const l = "http://localhost:3000/change-password/"+userID+"/"+token;

    const mailOptions = {
        from:"Sawaal",
        to:"sakthi9481@gmail.com",
        subject:"Password reset",
        text:"Click this link to reset your password "+l
    }

    const result = transport.sendMail(mailOptions);
    return result;
}



schedule.scheduleJob("0 0 * * *",()=>{
    UserModel.find({},function(err,users){
        console.log("i ran");
        if(err){
            console.log(err);
        }else{
            console.log("i ran inside");
            users.forEach((user)=>{
                if(user.challenges && Object.keys(user.challenges)!=0){
                    if(user.posted){
                        console.log("i ran true");
                        var obj = user.challenges;
                        obj.remainingDays-=1;
                        obj.completedDays+=1;
                        user.posted=false;
                        if(obj.remainingDays<0){
                            user.challengeCompleted = true;
                            if(user.Badges){
                                user.Badges+=1;
                            }else{
                                user.Badges=1;
                            }
                            user.completedChallenges.push(obj.challengeName);
                            user.challenges={};
                            user.postLink=[];
                            UserModel.findOneAndUpdate({_id:user._id},{challenges:{}},null,function(){
                                console.log("Updated");
                            })
                            user.save();
                        }else{
                            //console.log(obj);
                            UserModel.findOneAndUpdate({_id:user._id},{challenges:obj},null,function(){
                                console.log("Updated");
                            });
                            user.save();
                        } 
                        
                    }else{
                        console.log("i ran false");
                        var obj = user.challenges;
                        obj.remainingDays = obj.totalDays-1;
                        obj.completedDays =  1;
                        //delete post array;
                        user.postLink=[];
                        user.challengeDropped = 1;
                        UserModel.findOneAndUpdate({_id:user._id},{challenges:obj},null,function(){
                            console.log("Updated");
                        });
                        user.save();
                    }
                }
            });
        }
    });

    PostModel.deleteMany({},function(){
        console.log("All posts deleted");
    });
});