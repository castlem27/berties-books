// Create a new router
const express = require("express")
const router = express.Router()

// Handle our routes
router.get('/',function(req, res, next){
    res.render('index.ejs')
});

router.get('/about',function(req, res, next){
    res.render('about.ejs')
});

router.get('/books/addbook',function(req, res, next){
    res.render('addbook.ejs')
});


// Export the router object so index.js can access it
module.exports = router