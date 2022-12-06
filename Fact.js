const mongoose = require("mongoose")

var factsSchema = mongoose.Schema({
    current_page: Number,
    data: [
        {
            fact: String,
            length: Number,
        },
    ],
    first_page_url: String,
    from: Number,
    last_page: Number,
    last_page_url: String,
    links: [
        {
            url: String,
            label: String,
            active: Boolean,
        },
    ],
    next_page_url: String,
    path: String,
    per_page: Number,
    prev_page_url: Number,
    to: Number,
    total: Number,
});

module.exports = mongoose.model("Facts", factsSchema)