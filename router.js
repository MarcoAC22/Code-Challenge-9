const axios = require("axios");
const express = require("express");
const Breed = require("./Breed");
const Fact = require("./Fact");
const router = express.Router();
const mongoose = require("mongoose");
const user = require("./User");

const connectEnsureLogin = require("connect-ensure-login");
const passport = require("passport");

const facts = require("./cat_facts.json");
const breeds = require("./cat_breeds.json");
const users = require("./users.json");
const { json } = require("express");

router.get("/breeds", connectEnsureLogin.ensureLoggedIn(), async (req, res) => {
  const breeds = await Breed.find();
  await Promise.all(
    breeds[0].data.map(async (element) => {
      await axios.get(element.image).then(function (res) {
        element.image = res.request.res.responseUrl;
      });
    })
  );
  res.render("pages/breeds/index", {
    breeds: breeds[0].data,
    isAuthenticated: req.isAuthenticated(),
  });
});

router.get("/breeds/:title", async (req, res) => {
  const breeds = await Breed.findOne(
    { data: { $elemMatch: { breed: req.params.title } } },
    { "data.$": 1, name: 1 }
  );
  res.render("pages/breeds/details", {
    breed: breeds.data[0],
    isAuthenticated: req.isAuthenticated(),
  });
});

router.get("/facts", async (req, res) => {
  const facts = await Fact.find();
  res.render("pages/facts/index", {
    facts: facts[0].data,
    isAuthenticated: req.isAuthenticated(),
  });
});

router.post("/facts", async (req, res) => {
  const fact = new Fact(facts);
  await fact.save();
  res.send(fact);
});

router.post("/breeds", async (req, res) => {
  const breed = new Breed(breeds);
  await breed.save();
  res.send(breed);
});

router.post("/update", async (req, res) => {
  Breed.updateMany(
    {},
    {
      $set: {
        "data.$[].image":
          "https://thecatapi.com/api/images/get?format=src&type=gi",
      },
    },
    function (err, result) {
      if (err) {
        res.send(result);
      } else {
        res.send(result);
      }
    }
  );
});

router.get("/login", (req, res) => {
  res.render("pages/login", {
    title: "Login",
    isAuthenticated: req.isAuthenticated(),
  });

  router.get("/auth", (req,res)=>{
    res.render("pages/signup", {
      title: "signup",
      isAuthenticated: req.isAuthenticated(),
    })
  })

router.get("/signup", (req,res)=>{
  res.render("pages/signup", {
    title: "signup",
    isAuthenticated: req.isAuthenticated(),
  })
})

});
router.post("/addUsers", (req, res) => {
  users.data.map(async (element) => {
    user.register(
      { username: element.username, active: false },
      element.password
    );
  });
  res.send({ data: "done" });
});

router.post(
  "/login",
  passport.authenticate("local", {
    failureRedirect: "/login",
    successRedirect: "/breeds",
  }),
  (req, res) => {
    console.log(req.user);
  }
);

router.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});


router.get("/", async (req, res) => {
  const breeds = await Breed.find();

  let breed = breeds[0].data[Math.floor(Math.random() * breeds[0].data.length)];
  const facts = await Fact.find();
  let fact = facts[0].data[Math.floor(Math.random() * facts[0].data.length)];

  res.render("pages/index", {
    breed: breed,
    fact: fact,
    isAuthenticated: req.isAuthenticated(),
  });
});

module.exports = router;
