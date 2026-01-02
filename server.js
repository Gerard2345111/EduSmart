require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const fetch = (...args) => import("node-fetch").then(({default: fetch}) => fetch(...args));

const app = express();
app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGO_URI)
.then(()=>console.log("MongoDB connected"))
.catch(err=>console.log(err));

const User = mongoose.model("User", new mongoose.Schema({
  email:String,
  password:String
}));

const Listing = mongoose.model("Listing", new mongoose.Schema({
  title:String,
  price:Number,
  location:String,
  lat:Number,
  lng:Number,
  premium:{type:Boolean,default:false}
}));

function auth(req,res,next){
  const token = req.headers.authorization?.split(" ")[1];
  if(!token) return res.status(401).json({msg:"No token"});
  try{
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  }catch{
    res.status(401).json({msg:"Invalid token"});
  }
}

app.post("/api/auth/register", async(req,res)=>{
  const hash = await bcrypt.hash(req.body.password,10);
  await User.create({email:req.body.email,password:hash});
  res.json({msg:"Registered"});
});

app.post("/api/auth/login", async(req,res)=>{
  const user = await User.findOne({email:req.body.email});
  if(!user) return res.status(400).json({msg:"User not found"});
  const ok = await bcrypt.compare(req.body.password,user.password);
  if(!ok) return res.status(400).json({msg:"Wrong password"});
  const token = jwt.sign({id:user._id},process.env.JWT_SECRET);
  res.json({token});
});

app.get("/api/listings", async(req,res)=>{
  res.json(await Listing.find());
});

app.post("/api/listings", auth, async(req,res)=>{
  const listing = await Listing.create(req.body);
  res.json(listing);
});

app.post("/api/paystack/verify", auth, async(req,res)=>{
  const {reference, listing_id} = req.body;

  const r = await fetch(
    `https://api.paystack.co/transaction/verify/${reference}`,
    {
      headers:{ Authorization:`Bearer ${process.env.PAYSTACK_SECRET}` }
    }
  );

  const data = await r.json();
  if(data.data.status === "success"){
    await Listing.findByIdAndUpdate(listing_id,{premium:true});
    res.json({success:true});
  }else{
    res.status(400).json({success:false});
  }
});

app.listen(process.env.PORT || 3000);
